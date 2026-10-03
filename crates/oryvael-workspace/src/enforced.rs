#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{ControlError, ControlKind, load_verified_from_env, pin_bytes};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn create_from_files(
    principal_path: impl AsRef<Path>,
    registry_path: impl AsRef<Path>,
    request_path: impl AsRef<Path>,
) -> Result<WorkspaceResult, WorkspaceError> {
    let principal = load_verified_from_env(principal_path.as_ref(), ControlKind::PrincipalPolicy)
        .map_err(control_failure)?;
    let registry = load_verified_from_env(registry_path.as_ref(), ControlKind::WorkspaceRegistry)
        .map_err(control_failure)?;

    let request_path = canonical_input_file(request_path.as_ref())?;
    let request_bytes = fs::read(&request_path)?;
    let mut request: WorkspaceRequest = serde_json::from_slice(&request_bytes)?;
    let plan = load_verified_from_env(&request.change_plan, ControlKind::ChangePlan)
        .map_err(control_failure)?;

    let registry_value: WorkspaceRegistry = serde_json::from_slice(registry.bytes())?;
    if let Some(repository) = registry_value
        .repositories
        .iter()
        .find(|repository| repository.id == request.repository_id)
    {
        let workspace_root = absolute_path(&repository.workspace_root)?;
        fs::create_dir_all(&workspace_root)?;
        let target = fs::canonicalize(&workspace_root)?.join(&request.change_id);
        for control in [
            principal.path(),
            registry.path(),
            request_path.as_path(),
            plan.path(),
            principal.verified().signature_path.as_path(),
            registry.verified().signature_path.as_path(),
            plan.verified().signature_path.as_path(),
        ] {
            if control.starts_with(&target) {
                return Err(WorkspaceError::ControlFileInsideWorkspace(
                    control.to_path_buf(),
                ));
            }
        }
    }

    let principal_snapshot = principal
        .pin_snapshot("workspace-principal")
        .map_err(control_failure)?;
    let registry_snapshot = registry
        .pin_snapshot("workspace-registry")
        .map_err(control_failure)?;
    let plan_snapshot = plan
        .pin_snapshot("workspace-plan")
        .map_err(control_failure)?;

    request.change_plan = plan_snapshot.path().to_path_buf();
    let normalized_request = serde_json::to_vec(&request)?;
    let request_snapshot = pin_bytes(
        "workspace-request",
        file_name(&request_path, "request.json"),
        &normalized_request,
    )
    .map_err(control_failure)?;

    inner::create_from_files(
        principal_snapshot.path(),
        registry_snapshot.path(),
        request_snapshot.path(),
    )
}

fn canonical_input_file(path: &Path) -> Result<PathBuf, WorkspaceError> {
    let path = fs::canonicalize(absolute_path(path)?)?;
    if !path.is_file() {
        return Err(WorkspaceError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("control path is not a file: {}", path.display()),
        )));
    }
    Ok(path)
}

fn absolute_path(path: &Path) -> Result<PathBuf, io::Error> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn file_name<'a>(path: &'a Path, fallback: &'a str) -> &'a str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback)
}

fn control_failure(error: ControlError) -> WorkspaceError {
    WorkspaceError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
