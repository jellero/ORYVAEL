#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{ControlError, ControlKind, verify_from_env};
use std::io;
use std::path::Path;

pub fn build_from_files(
    plan_path: impl AsRef<Path>,
    evidence_path: impl AsRef<Path>,
) -> Result<ProofPackage, ProofError> {
    let plan_path = plan_path.as_ref();
    let evidence_path = evidence_path.as_ref();

    verify_from_env(plan_path, ControlKind::ChangePlan).map_err(control_failure)?;
    inner::build_from_files(plan_path, evidence_path)
}

pub fn build_audited_from_files(
    plan_path: impl AsRef<Path>,
    input_path: impl AsRef<Path>,
) -> Result<ProofPackage, ProofError> {
    let plan_path = plan_path.as_ref();
    let input_path = input_path.as_ref();

    verify_from_env(plan_path, ControlKind::ChangePlan).map_err(control_failure)?;
    inner::build_audited_from_files(plan_path, input_path)
}

fn control_failure(error: ControlError) -> ProofError {
    ProofError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
