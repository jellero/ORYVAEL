#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{ControlError, ControlKind, verify_from_env};
use oryvael_supervisor::JobResult;
use std::fs;
use std::io;
use std::path::Path;

pub fn run_brokered_from_files(
    principal_path: impl AsRef<Path>,
    catalog_path: impl AsRef<Path>,
    invocation_path: impl AsRef<Path>,
) -> Result<JobResult, ToolBrokerError> {
    let principal_path = principal_path.as_ref();
    let catalog_path = catalog_path.as_ref();
    let invocation_path = invocation_path.as_ref();

    verify_from_env(principal_path, ControlKind::PrincipalPolicy).map_err(control_failure)?;
    verify_from_env(catalog_path, ControlKind::ToolCatalog).map_err(control_failure)?;

    let invocation: ToolInvocation = serde_json::from_slice(&fs::read(invocation_path)?)?;
    verify_from_env(&invocation.change_plan, ControlKind::ChangePlan).map_err(control_failure)?;

    inner::run_brokered_from_files(principal_path, catalog_path, invocation_path)
}

fn control_failure(error: ControlError) -> ToolBrokerError {
    ToolBrokerError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
