#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{ControlError, ControlKind, load_verified_from_env, pin_bytes};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn run_from_files(
    principal_path: impl AsRef<Path>,
    job_path: impl AsRef<Path>,
) -> Result<JobResult, SupervisorError> {
    let principal = load_verified_from_env(principal_path.as_ref(), ControlKind::PrincipalPolicy)
        .map_err(control_failure)?;
    let job_path = canonical_input_file(job_path.as_ref())?;
    let job_bytes = fs::read(&job_path)?;
    let spec: JobSpec = serde_json::from_slice(&job_bytes)?;

    let workspace = absolute_path(&spec.workspace)?;
    fs::create_dir_all(&workspace)?;
    let workspace = fs::canonicalize(workspace)?;
    for control in [principal.path(), job_path.as_path()] {
        if control.starts_with(&workspace) {
            return Err(SupervisorError::ControlFileInsideWorkspace(
                control.to_path_buf(),
            ));
        }
    }

    let principal_snapshot = principal
        .pin_snapshot("supervisor-principal")
        .map_err(control_failure)?;
    let job_snapshot = pin_bytes(
        "supervisor-job",
        file_name(&job_path, "job.json"),
        &job_bytes,
    )
    .map_err(control_failure)?;

    inner::run_from_files(principal_snapshot.path(), job_snapshot.path())
}

fn canonical_input_file(path: &Path) -> Result<PathBuf, SupervisorError> {
    let path = fs::canonicalize(absolute_path(path)?)?;
    if !path.is_file() {
        return Err(SupervisorError::InvalidSpec(format!(
            "control path is not a file: {}",
            path.display()
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

fn control_failure(error: ControlError) -> SupervisorError {
    SupervisorError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
