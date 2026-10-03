#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{ControlError, ControlKind, verify_from_env};
use std::fs;
use std::io;
use std::path::Path;

pub fn create_from_files(
    principal_path: impl AsRef<Path>,
    registry_path: impl AsRef<Path>,
    request_path: impl AsRef<Path>,
) -> Result<WorkspaceResult, WorkspaceError> {
    let principal_path = principal_path.as_ref();
    let registry_path = registry_path.as_ref();
    let request_path = request_path.as_ref();

    verify_from_env(principal_path, ControlKind::PrincipalPolicy).map_err(control_failure)?;
    verify_from_env(registry_path, ControlKind::WorkspaceRegistry).map_err(control_failure)?;

    let request: WorkspaceRequest = serde_json::from_slice(&fs::read(request_path)?)?;
    verify_from_env(&request.change_plan, ControlKind::ChangePlan).map_err(control_failure)?;

    inner::create_from_files(principal_path, registry_path, request_path)
}

fn control_failure(error: ControlError) -> WorkspaceError {
    WorkspaceError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
