#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{ControlError, ControlKind, load_verified_from_env, pin_bytes};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn build_from_files(
    plan_path: impl AsRef<Path>,
    evidence_path: impl AsRef<Path>,
) -> Result<ProofPackage, ProofError> {
    let plan = load_verified_from_env(plan_path.as_ref(), ControlKind::ChangePlan)
        .map_err(control_failure)?;
    let evidence_path = canonical_input_file(evidence_path.as_ref())?;
    let evidence_bytes = fs::read(&evidence_path)?;

    let plan_snapshot = plan.pin_snapshot("proof-plan").map_err(control_failure)?;
    let evidence_snapshot = pin_bytes(
        "proof-evidence",
        file_name(&evidence_path, "evidence.json"),
        &evidence_bytes,
    )
    .map_err(control_failure)?;

    inner::build_from_files(plan_snapshot.path(), evidence_snapshot.path())
}

pub fn build_audited_from_files(
    plan_path: impl AsRef<Path>,
    input_path: impl AsRef<Path>,
) -> Result<ProofPackage, ProofError> {
    let plan = load_verified_from_env(plan_path.as_ref(), ControlKind::ChangePlan)
        .map_err(control_failure)?;
    let input_path = canonical_input_file(input_path.as_ref())?;
    let input_bytes = fs::read(&input_path)?;

    let plan_snapshot = plan
        .pin_snapshot("proof-audited-plan")
        .map_err(control_failure)?;
    let input_snapshot = pin_bytes(
        "proof-audited-input",
        file_name(&input_path, "audited-proof-input.json"),
        &input_bytes,
    )
    .map_err(control_failure)?;

    inner::build_audited_from_files(plan_snapshot.path(), input_snapshot.path())
}

fn canonical_input_file(path: &Path) -> Result<PathBuf, ProofError> {
    let path = fs::canonicalize(path)?;
    if !path.is_file() {
        return Err(ProofError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("input path is not a file: {}", path.display()),
        )));
    }
    Ok(path)
}

fn file_name<'a>(path: &'a Path, fallback: &'a str) -> &'a str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback)
}

fn control_failure(error: ControlError) -> ProofError {
    ProofError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
