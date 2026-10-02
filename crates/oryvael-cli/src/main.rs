#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use oryvael_approval::{public_key_from_private_file, sign_from_files, verify_from_files};
use oryvael_arch::Architecture;
use oryvael_audit::{AuditLedger, AuditRecord};
use oryvael_evidence::extract_from_jsonl;
use oryvael_proof::{build_audited_from_files, build_from_files};
use oryvael_protocol::{Operation, Principal};
use oryvael_release::{
    approval_context_from_files, check_from_files as check_release_from_files,
    check_from_files_with_approvals,
};
use oryvael_supervisor::{host_status, run_from_files};
use oryvael_tool_broker::run_brokered_from_files;
use oryvael_workspace::create_from_files as create_workspace_from_files;
use std::{error::Error, fs, io, process};

#[derive(Debug, Parser)]
#[command(
    name = "oryvael",
    version,
    about = "ORYVAEL trusted-core reference CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ArchCheck {
        file: String,
    },
    PolicyCheck {
        principal: String,
        operation: String,
    },
    AuditVerify {
        file: String,
    },
    Supervise {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        job: String,
    },
    SupervisorDoctor,
    ToolRun {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        catalog: String,
        #[arg(long)]
        invocation: String,
    },
    ProofBuild {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        evidence: String,
    },
    ProofBuildAudited {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        input: String,
    },
    WorkspaceCreate {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        request: String,
    },
    EvidenceExtract {
        #[arg(long)]
        audit: String,
        #[arg(long)]
        operation_id: String,
    },
    ReleaseContext {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        artifact_name: String,
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        ring: String,
    },
    ApprovalPublicKey {
        #[arg(long)]
        private_key: String,
    },
    ApprovalSign {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        context: String,
    },
    ApprovalVerify {
        #[arg(long)]
        policy: String,
        #[arg(long)]
        bundle: String,
        #[arg(long)]
        context: String,
    },
    ReleaseCheck {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        artifact_name: String,
        #[arg(long)]
        artifact: String,
        #[arg(long)]
        ring: String,
        #[arg(long)]
        approval_policy: Option<String>,
        #[arg(long)]
        approval_bundle: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::ArchCheck { file } => {
            let architecture: Architecture = read_json(&file)?;
            let violations = oryvael_arch::validate(&architecture);
            println!("{}", serde_json::to_string_pretty(&violations)?);
            if !violations.is_empty() {
                process::exit(2);
            }
        }
        Command::PolicyCheck {
            principal,
            operation,
        } => {
            let principal: Principal = read_json(&principal)?;
            let operation: Operation = read_json(&operation)?;
            let decision = oryvael_policy::evaluate(&principal, &operation);
            println!("{}", serde_json::to_string_pretty(&decision)?);
            if !decision.allowed {
                process::exit(2);
            }
        }
        Command::AuditVerify { file } => {
            let content = fs::read_to_string(file)?;
            let mut records = Vec::new();
            for (index, line) in content.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let record: AuditRecord = serde_json::from_str(line).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid audit JSON at line {}: {error}", index + 1),
                    )
                })?;
                records.push(record);
            }

            let ledger = AuditLedger::from_records(records);
            ledger.verify()?;
            println!("audit chain valid: {} records", ledger.records().len());
        }
        Command::Supervise { principal, job } => {
            let result = run_from_files(principal, job)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if !result.success {
                process::exit(3);
            }
        }
        Command::SupervisorDoctor => {
            let status = host_status();
            println!("{}", serde_json::to_string_pretty(&status)?);
            if !status.ready_for_basic_sandbox {
                process::exit(2);
            }
        }
        Command::ToolRun {
            principal,
            catalog,
            invocation,
        } => {
            let result = run_brokered_from_files(principal, catalog, invocation)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if !result.success {
                process::exit(3);
            }
        }
        Command::ProofBuild { plan, evidence } => {
            let package = build_from_files(plan, evidence)?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            if !package.eligible {
                process::exit(4);
            }
        }
        Command::ProofBuildAudited { plan, input } => {
            let package = build_audited_from_files(plan, input)?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            if !package.eligible {
                process::exit(4);
            }
        }
        Command::WorkspaceCreate {
            principal,
            registry,
            request,
        } => {
            let result = create_workspace_from_files(principal, registry, request)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::EvidenceExtract {
            audit,
            operation_id,
        } => {
            let evidence = extract_from_jsonl(audit, &operation_id)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
        Command::ReleaseContext {
            plan,
            input,
            artifact_name,
            artifact,
            ring,
        } => {
            let context =
                approval_context_from_files(plan, input, &artifact_name, artifact, &ring)?;
            println!("{}", serde_json::to_string_pretty(&context)?);
        }
        Command::ApprovalPublicKey { private_key } => {
            println!("{}", public_key_from_private_file(private_key)?);
        }
        Command::ApprovalSign {
            private_key,
            signer_id,
            context,
        } => {
            let approval = sign_from_files(private_key, &signer_id, context)?;
            println!("{}", serde_json::to_string_pretty(&approval)?);
        }
        Command::ApprovalVerify {
            policy,
            bundle,
            context,
        } => {
            let verification = verify_from_files(policy, bundle, context)?;
            println!("{}", serde_json::to_string_pretty(&verification)?);
            if !verification.eligible {
                process::exit(6);
            }
        }
        Command::ReleaseCheck {
            plan,
            input,
            artifact_name,
            artifact,
            ring,
            approval_policy,
            approval_bundle,
        } => {
            let decision = match (approval_policy, approval_bundle) {
                (Some(policy), Some(bundle)) => check_from_files_with_approvals(
                    plan,
                    input,
                    &artifact_name,
                    artifact,
                    &ring,
                    policy,
                    bundle,
                )?,
                (None, None) => {
                    check_release_from_files(plan, input, &artifact_name, artifact, &ring)?
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--approval-policy and --approval-bundle must be provided together",
                    )
                    .into());
                }
            };
            println!("{}", serde_json::to_string_pretty(&decision)?);
            if !decision.eligible {
                process::exit(5);
            }
        }
    }

    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}
