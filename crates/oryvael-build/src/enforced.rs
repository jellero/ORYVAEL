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
    input_path: impl AsRef<Path>,
) -> Result<BuildManifest, BuildManifestError> {
    let plan = load_verified_from_env(plan_path.as_ref(), ControlKind::ChangePlan)
        .map_err(control_failure)?;
    let input_path = canonical_input_file(input_path.as_ref())?;
    let input_bytes = fs::read(&input_path)?;

    let plan_snapshot = plan.pin_snapshot("build-plan").map_err(control_failure)?;
    let input_snapshot = pin_bytes(
        "build-input",
        file_name(&input_path, "build-input.json"),
        &input_bytes,
    )
    .map_err(control_failure)?;

    inner::build_from_files(plan_snapshot.path(), input_snapshot.path())
}

fn canonical_input_file(path: &Path) -> Result<PathBuf, BuildManifestError> {
    let path = fs::canonicalize(path)?;
    if !path.is_file() {
        return Err(BuildManifestError::Io(io::Error::new(
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

fn control_failure(error: ControlError) -> BuildManifestError {
    BuildManifestError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
