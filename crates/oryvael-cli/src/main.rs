#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use oryvael_arch::Architecture;
use oryvael_audit::{AuditLedger, AuditRecord};
use oryvael_protocol::{Operation, Principal};
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
    }

    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}
