#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{ControlError, ControlKind, verify_from_env};
use std::io;
use std::path::Path;

pub fn run_from_files(
    principal_path: impl AsRef<Path>,
    job_path: impl AsRef<Path>,
) -> Result<JobResult, SupervisorError> {
    let principal_path = principal_path.as_ref();
    let job_path = job_path.as_ref();

    verify_from_env(principal_path, ControlKind::PrincipalPolicy).map_err(control_failure)?;
    inner::run_from_files(principal_path, job_path)
}

fn control_failure(error: ControlError) -> SupervisorError {
    SupervisorError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
