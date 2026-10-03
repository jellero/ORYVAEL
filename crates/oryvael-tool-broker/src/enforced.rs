#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use oryvael_control::{
    ControlError, ControlKind, SnapshotFile, load_verified_from_env, pin_bytes,
};
use oryvael_supervisor::JobResult;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn run_brokered_from_files(
    principal_path: impl AsRef<Path>,
    catalog_path: impl AsRef<Path>,
    invocation_path: impl AsRef<Path>,
) -> Result<JobResult, ToolBrokerError> {
    let principal = load_verified_from_env(principal_path.as_ref(), ControlKind::PrincipalPolicy)
        .map_err(control_failure)?;
    let catalog = load_verified_from_env(catalog_path.as_ref(), ControlKind::ToolCatalog)
        .map_err(control_failure)?;

    let invocation_path = canonical_input_file(invocation_path.as_ref())?;
    let invocation_bytes = fs::read(&invocation_path)?;
    let mut invocation: ToolInvocation = serde_json::from_slice(&invocation_bytes)?;
    let plan = load_verified_from_env(&invocation.change_plan, ControlKind::ChangePlan)
        .map_err(control_failure)?;

    let workspace = absolute_path(&invocation.workspace)?;
    fs::create_dir_all(&workspace)?;
    let workspace = fs::canonicalize(workspace)?;

    let legacy_trust_path = canonical_input_file(&catalog_sidecar_path(catalog.path(), "trust"))?;
    let legacy_signature_path =
        canonical_input_file(&catalog_sidecar_path(catalog.path(), "signature"))?;
    let legacy_trust_bytes = fs::read(&legacy_trust_path)?;
    let legacy_signature_bytes = fs::read(&legacy_signature_path)?;

    for control in [
        principal.path(),
        catalog.path(),
        invocation_path.as_path(),
        plan.path(),
        principal.verified().signature_path.as_path(),
        catalog.verified().signature_path.as_path(),
        plan.verified().signature_path.as_path(),
        legacy_trust_path.as_path(),
        legacy_signature_path.as_path(),
    ] {
        if control.starts_with(&workspace) {
            return Err(ToolBrokerError::ControlFileInsideWorkspace(
                control.to_path_buf(),
            ));
        }
    }

    let principal_snapshot = principal
        .pin_snapshot("tool-principal")
        .map_err(control_failure)?;
    let legacy_trust_name = file_name(&legacy_trust_path, "catalog.trust.json").to_owned();
    let legacy_signature_name =
        file_name(&legacy_signature_path, "catalog.signature.json").to_owned();
    let catalog_snapshot = catalog
        .pin_snapshot_with_siblings(
            "tool-catalog",
            &[
                SnapshotFile {
                    file_name: legacy_trust_name,
                    bytes: legacy_trust_bytes,
                },
                SnapshotFile {
                    file_name: legacy_signature_name,
                    bytes: legacy_signature_bytes,
                },
            ],
        )
        .map_err(control_failure)?;
    let plan_snapshot = plan
        .pin_snapshot("tool-plan")
        .map_err(control_failure)?;

    invocation.change_plan = plan_snapshot.path().to_path_buf();
    let normalized_invocation = serde_json::to_vec(&invocation)?;
    let invocation_snapshot = pin_bytes(
        "tool-invocation",
        file_name(&invocation_path, "invocation.json"),
        &normalized_invocation,
    )
    .map_err(control_failure)?;

    inner::run_brokered_from_files(
        principal_snapshot.path(),
        catalog_snapshot.path(),
        invocation_snapshot.path(),
    )
}

fn catalog_sidecar_path(catalog_path: &Path, kind: &str) -> PathBuf {
    let stem = catalog_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("catalog");
    catalog_path.with_file_name(format!("{stem}.{kind}.json"))
}

fn canonical_input_file(path: &Path) -> Result<PathBuf, ToolBrokerError> {
    let path = fs::canonicalize(absolute_path(path)?)?;
    if !path.is_file() {
        return Err(ToolBrokerError::InvalidTool(format!(
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

fn control_failure(error: ControlError) -> ToolBrokerError {
    ToolBrokerError::Io(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("control verification failed: {error}"),
    ))
}
