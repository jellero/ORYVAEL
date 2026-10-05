#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use oryvael_approval::{public_key_from_private_file, sign_from_files, verify_from_files};
use oryvael_arch::Architecture;
use oryvael_audit::{AuditLedger, AuditRecord};
use oryvael_build::{
    build_from_files as build_manifest_from_files, compare_from_files as compare_builds_from_files,
};
use oryvael_control::{
    ControlKind, public_key_from_private_file as control_public_key_from_private_file,
    sign_from_files as sign_control_from_files, verify_from_env as verify_control_from_env,
    verify_from_files as verify_control_from_files,
};
use oryvael_evidence::extract_from_jsonl;
use oryvael_proof::{build_audited_from_files, build_from_files};
use oryvael_protocol::{Operation, Principal, WorkloadManifest, validate_workload_manifest};
use oryvael_release::{
    approval_context_from_files, check_from_files as check_release_from_files,
    check_from_files_with_approvals,
};
use oryvael_supervisor::{host_status, run_from_files};
use oryvael_tool_broker::run_brokered_from_files;
use oryvael_workspace::create_from_files as create_workspace_from_files;
use serde_json::Value;
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
    WorkloadCheck {
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
    ControlPublicKey {
        #[arg(long)]
        private_key: String,
    },
    ControlSign {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        key_version: u64,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        artifact: String,
    },
    ControlVerify {
        #[arg(long)]
        root_policy: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        artifact: String,
    },
    BuildManifest {
        #[arg(long)]
        plan: String,
        #[arg(long)]
        input: String,
    },
    BuildCompare {
        #[arg(long)]
        left: String,
        #[arg(long)]
        right: String,
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
        Command::WorkloadCheck { file } => {
            let manifest: WorkloadManifest = read_json(&file)?;
            let violations = validate_workload_manifest(&manifest);
            println!("{}", serde_json::to_string_pretty(&violations)?);
            if !violations.is_empty() {
                process::exit(2);
            }
        }
        Command::PolicyCheck {
            principal,
            operation,
        } => {
            verify_control_from_env(&principal, ControlKind::PrincipalPolicy)?;
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
            verify_control_from_env(&principal, ControlKind::PrincipalPolicy)?;
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
            verify_control_from_env(&principal, ControlKind::PrincipalPolicy)?;
            verify_control_from_env(&catalog, ControlKind::ToolCatalog)?;
            let plan = control_reference(&invocation, "change_plan")?;
            verify_control_from_env(&plan, ControlKind::ChangePlan)?;
            let result = run_brokered_from_files(principal, catalog, invocation)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if !result.success {
                process::exit(3);
            }
        }
        Command::ProofBuild { plan, evidence } => {
            verify_control_from_env(&plan, ControlKind::ChangePlan)?;
            let package = build_from_files(plan, evidence)?;
            println!("{}", serde_json::to_string_pretty(&package)?);
            if !package.eligible {
                process::exit(4);
            }
        }
        Command::ProofBuildAudited { plan, input } => {
            verify_control_from_env(&plan, ControlKind::ChangePlan)?;
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
            verify_control_from_env(&principal, ControlKind::PrincipalPolicy)?;
            verify_control_from_env(&registry, ControlKind::WorkspaceRegistry)?;
            let plan = control_reference(&request, "change_plan")?;
            verify_control_from_env(&plan, ControlKind::ChangePlan)?;
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
            verify_control_from_env(&plan, ControlKind::ChangePlan)?;
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
        Command::ControlPublicKey { private_key } => {
            println!("{}", control_public_key_from_private_file(private_key)?);
        }
        Command::ControlSign {
            private_key,
            signer_id,
            key_version,
            kind,
            artifact,
        } => {
            let kind = ControlKind::parse(&kind)?;
            let signature =
                sign_control_from_files(private_key, &signer_id, key_version, kind, artifact)?;
            println!("{}", serde_json::to_string_pretty(&signature)?);
        }
        Command::ControlVerify {
            root_policy,
            kind,
            artifact,
        } => {
            let kind = ControlKind::parse(&kind)?;
            let verified = verify_control_from_files(artifact, root_policy, kind)?;
            println!("{}", serde_json::to_string_pretty(&verified)?);
        }
        Command::BuildManifest { plan, input } => {
            verify_control_from_env(&plan, ControlKind::ChangePlan)?;
            let manifest = build_manifest_from_files(plan, input)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::BuildCompare { left, right } => {
            let report = compare_builds_from_files(left, right)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.reproducible {
                process::exit(7);
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
            verify_control_from_env(&plan, ControlKind::ChangePlan)?;
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

fn control_reference(path: &str, field: &str) -> Result<String, Box<dyn Error>> {
    let value: Value = read_json(path)?;
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("control input {path} is missing string field {field}"),
            )
            .into()
        })
}
