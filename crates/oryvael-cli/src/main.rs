#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use oryvael_arch::Architecture;
use oryvael_audit::{AuditLedger, AuditRecord};
use oryvael_proof::build_from_files;
use oryvael_protocol::{Operation, Principal};
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
    WorkspaceCreate {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        registry: String,
        #[arg(long)]
        request: String,
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
        Command::WorkspaceCreate {
            principal,
            registry,
            request,
        } => {
            let result = create_workspace_from_files(principal, registry, request)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}
