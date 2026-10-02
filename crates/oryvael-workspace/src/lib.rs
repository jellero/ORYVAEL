#![forbid(unsafe_code)]

use oryvael_audit::{AuditError, JsonlAuditJournal};
use oryvael_policy::evaluate;
use oryvael_protocol::{AuditDecision, AuditEvent, ChangePlan, Operation, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

static OP_COUNTER: AtomicU64 = AtomicU64::new(1);
const GIT: &str = "/usr/bin/git";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceRegistry {
    pub version: String,
    pub repositories: Vec<RepositoryDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositoryDefinition {
    pub id: String,
    pub path: PathBuf,
    pub workspace_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceRequest {
    pub principal: String,
    pub change_id: String,
    pub change_plan: PathBuf,
    pub repository_id: String,
    pub base_ref: String,
    pub audit_log: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceResult {
    pub operation_id: String,
    pub repository_id: String,
    pub workspace: PathBuf,
    pub branch: String,
    pub base_commit: String,
    pub audit_log: PathBuf,
}

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("principal mismatch: policy is {policy}, request is {request}")]
    PrincipalMismatch { policy: String, request: String },
    #[error("change id mismatch: plan is {plan}, request is {request}")]
    ChangeIdMismatch { plan: String, request: String },
    #[error("workspace request principal must equal change-plan producer")]
    ProducerMismatch,
    #[error("unsafe change id: {0}")]
    UnsafeChangeId(String),
    #[error("unknown repository id: {0}")]
    UnknownRepository(String),
    #[error("duplicate repository id: {0}")]
    DuplicateRepository(String),
    #[error("change plan is missing required capability: {0}")]
    MissingPlanCapability(String),
    #[error("workspace target already exists: {0}")]
    TargetExists(PathBuf),
    #[error("generated branch already exists: {0}")]
    BranchExists(String),
    #[error("invalid base ref: {0}")]
    InvalidBaseRef(String),
    #[error("git command failed: {0}")]
    Git(String),
    #[error("policy denied {resource}.{action} on {target}: {reason}")]
    PolicyDenied {
        resource: String,
        action: String,
        target: String,
        reason: String,
    },
    #[error("audit log must be outside the provisioned workspace: {0}")]
    AuditInsideWorkspace(PathBuf),
    #[error("control file must be outside the provisioned workspace: {0}")]
    ControlFileInsideWorkspace(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit error: {0}")]
    Audit(#[from] AuditError),
}

pub fn create_from_files(
    principal_path: impl AsRef<Path>,
    registry_path: impl AsRef<Path>,
    request_path: impl AsRef<Path>,
) -> Result<WorkspaceResult, WorkspaceError> {
    let principal_path = canonical_file(principal_path.as_ref())?;
    let registry_path = canonical_file(registry_path.as_ref())?;
    let request_path = canonical_file(request_path.as_ref())?;

    let principal_content = fs::read_to_string(&principal_path)?;
    let registry_content = fs::read_to_string(&registry_path)?;
    let request_content = fs::read_to_string(&request_path)?;

    let principal: Principal = serde_json::from_str(&principal_content)?;
    let registry: WorkspaceRegistry = serde_json::from_str(&registry_content)?;
    let request: WorkspaceRequest = serde_json::from_str(&request_content)?;
    validate_registry(&registry)?;

    if principal.principal != request.principal {
        return Err(WorkspaceError::PrincipalMismatch {
            policy: principal.principal,
            request: request.principal,
        });
    }

    if !is_safe_id(&request.change_id) {
        return Err(WorkspaceError::UnsafeChangeId(request.change_id));
    }

    let plan_path = canonical_file(&request.change_plan)?;
    let plan_content = fs::read_to_string(&plan_path)?;
    let plan: ChangePlan = serde_json::from_str(&plan_content)?;

    if plan.id != request.change_id {
        return Err(WorkspaceError::ChangeIdMismatch {
            plan: plan.id,
            request: request.change_id,
        });
    }
    if plan.producer != principal.principal {
        return Err(WorkspaceError::ProducerMismatch);
    }

    let repository = registry
        .repositories
        .iter()
        .find(|repository| repository.id == request.repository_id)
        .ok_or_else(|| WorkspaceError::UnknownRepository(request.repository_id.clone()))?;

    for capability in [
        format!("repository:{}:read", repository.id),
        "workspace:provision".into(),
        "git:branch:create".into(),
    ] {
        if !plan
            .requested_capabilities
            .iter()
            .any(|requested| requested == &capability)
        {
            return Err(WorkspaceError::MissingPlanCapability(capability));
        }
    }

    let repository_path = fs::canonicalize(absolute_path(&repository.path)?)?;
    let workspace_root = absolute_path(&repository.workspace_root)?;
    fs::create_dir_all(&workspace_root)?;
    let workspace_root = fs::canonicalize(workspace_root)?;

    let target = workspace_root.join(&request.change_id);
    if target.exists() {
        return Err(WorkspaceError::TargetExists(target));
    }

    let branch = format!("oryvael/{}", request.change_id);
    validate_branch(&branch)?;

    let audit_log = external_file_path(&request.audit_log)?;
    if audit_log.starts_with(&target) {
        return Err(WorkspaceError::AuditInsideWorkspace(audit_log));
    }

    for control in [&principal_path, &registry_path, &request_path, &plan_path] {
        if control.starts_with(&target) {
            return Err(WorkspaceError::ControlFileInsideWorkspace(control.clone()));
        }
    }

    let mut audit = JsonlAuditJournal::open(&audit_log)?;
    let operation_id = new_operation_id();

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "principal_policy_sha256".into(),
        sha256_hex(principal_content.as_bytes()),
    );
    metadata.insert(
        "workspace_registry_sha256".into(),
        sha256_hex(registry_content.as_bytes()),
    );
    metadata.insert(
        "workspace_request_sha256".into(),
        sha256_hex(request_content.as_bytes()),
    );
    metadata.insert(
        "change_plan_sha256".into(),
        sha256_hex(plan_content.as_bytes()),
    );
    metadata.insert("repository_id".into(), repository.id.clone());
    metadata.insert("branch".into(), branch.clone());

    audit.append(AuditEvent {
        timestamp_ns: now_ns(),
        actor: principal.principal.clone(),
        action: "workspace.provision.request".into(),
        target: target.to_string_lossy().into_owned(),
        decision: AuditDecision::Observed,
        change_id: Some(plan.id.clone()),
        operation_id: Some(operation_id.clone()),
        metadata,
    })?;

    authorize(
        &mut audit,
        &principal,
        &plan.id,
        &operation_id,
        Operation {
            resource: "repository".into(),
            action: "read".into(),
            target: Some(repository.id.clone()),
        },
    )?;

    authorize(
        &mut audit,
        &principal,
        &plan.id,
        &operation_id,
        Operation {
            resource: "workspace".into(),
            action: "provision".into(),
            target: Some(target.to_string_lossy().into_owned()),
        },
    )?;

    authorize(
        &mut audit,
        &principal,
        &plan.id,
        &operation_id,
        Operation {
            resource: "git_branch".into(),
            action: "create".into(),
            target: Some(branch.clone()),
        },
    )?;

    if branch_exists(&repository_path, &branch)? {
        return Err(WorkspaceError::BranchExists(branch));
    }

    let base_commit = resolve_commit(&repository_path, &request.base_ref)?;

    let output = Command::new(GIT)
        .arg("-C")
        .arg(&repository_path)
        .args(["worktree", "add", "-b"])
        .arg(&branch)
        .arg(&target)
        .arg(&base_commit)
        .output()?;

    if !output.status.success() {
        rollback_partial(&repository_path, &target, &branch);
        let detail = output_summary(&output);
        let mut failure = BTreeMap::new();
        failure.insert("error".into(), detail.clone());
        let _ = audit.append(AuditEvent {
            timestamp_ns: now_ns(),
            actor: principal.principal.clone(),
            action: "workspace.provision".into(),
            target: target.to_string_lossy().into_owned(),
            decision: AuditDecision::Failed,
            change_id: Some(plan.id.clone()),
            operation_id: Some(operation_id.clone()),
            metadata: failure,
        });
        return Err(WorkspaceError::Git(detail));
    }

    let workspace = fs::canonicalize(&target)?;

    let mut success = BTreeMap::new();
    success.insert("base_commit".into(), base_commit.clone());
    success.insert("branch".into(), branch.clone());
    success.insert("repository_id".into(), repository.id.clone());
    audit.append(AuditEvent {
        timestamp_ns: now_ns(),
        actor: principal.principal,
        action: "workspace.provision".into(),
        target: workspace.to_string_lossy().into_owned(),
        decision: AuditDecision::Allowed,
        change_id: Some(plan.id),
        operation_id: Some(operation_id.clone()),
        metadata: success,
    })?;

    Ok(WorkspaceResult {
        operation_id,
        repository_id: repository.id.clone(),
        workspace,
        branch,
        base_commit,
        audit_log: audit.path().to_path_buf(),
    })
}

fn authorize(
    audit: &mut JsonlAuditJournal,
    principal: &Principal,
    change_id: &str,
    operation_id: &str,
    operation: Operation,
) -> Result<(), WorkspaceError> {
    let decision = evaluate(principal, &operation);
    let target = operation.target.clone().unwrap_or_default();

    let mut metadata = BTreeMap::new();
    metadata.insert("resource".into(), operation.resource.clone());
    metadata.insert("action".into(), operation.action.clone());
    metadata.insert("reason".into(), decision.reason.clone());
    if let Some(index) = decision.matched_grant {
        metadata.insert("matched_grant".into(), index.to_string());
    }

    audit.append(AuditEvent {
        timestamp_ns: now_ns(),
        actor: principal.principal.clone(),
        action: "policy.evaluate".into(),
        target: target.clone(),
        decision: if decision.allowed {
            AuditDecision::Allowed
        } else {
            AuditDecision::Denied
        },
        change_id: Some(change_id.into()),
        operation_id: Some(operation_id.into()),
        metadata,
    })?;

    if decision.allowed {
        Ok(())
    } else {
        Err(WorkspaceError::PolicyDenied {
            resource: operation.resource,
            action: operation.action,
            target,
            reason: decision.reason,
        })
    }
}

fn validate_registry(registry: &WorkspaceRegistry) -> Result<(), WorkspaceError> {
    let mut ids = BTreeSet::new();
    for repository in &registry.repositories {
        if repository.id.trim().is_empty() || !is_safe_id(&repository.id) {
            return Err(WorkspaceError::UnknownRepository(repository.id.clone()));
        }
        if !ids.insert(repository.id.as_str()) {
            return Err(WorkspaceError::DuplicateRepository(repository.id.clone()));
        }
    }
    Ok(())
}

fn validate_branch(branch: &str) -> Result<(), WorkspaceError> {
    let status = Command::new(GIT)
        .args(["check-ref-format", "--branch"])
        .arg(branch)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(WorkspaceError::UnsafeChangeId(branch.into()))
    }
}

fn branch_exists(repository: &Path, branch: &str) -> Result<bool, WorkspaceError> {
    let reference = format!("refs/heads/{branch}");
    let status = Command::new(GIT)
        .arg("-C")
        .arg(repository)
        .args(["show-ref", "--verify", "--quiet"])
        .arg(reference)
        .status()?;
    Ok(status.success())
}

fn resolve_commit(repository: &Path, base_ref: &str) -> Result<String, WorkspaceError> {
    if base_ref.trim().is_empty() || base_ref.starts_with('-') {
        return Err(WorkspaceError::InvalidBaseRef(base_ref.into()));
    }

    let commitish = format!("{base_ref}^{{commit}}");
    let output = Command::new(GIT)
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "--verify", "--end-of-options"])
        .arg(commitish)
        .output()?;

    if !output.status.success() {
        return Err(WorkspaceError::InvalidBaseRef(base_ref.into()));
    }

    let commit = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if commit.is_empty() || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(WorkspaceError::InvalidBaseRef(base_ref.into()));
    }

    Ok(commit)
}

fn rollback_partial(repository: &Path, target: &Path, branch: &str) {
    if target.exists() {
        let _ = Command::new(GIT)
            .arg("-C")
            .arg(repository)
            .args(["worktree", "remove", "--force"])
            .arg(target)
            .status();
    }

    let _ = Command::new(GIT)
        .arg("-C")
        .arg(repository)
        .args(["branch", "-D"])
        .arg(branch)
        .status();
}

fn output_summary(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    detail.chars().take(512).collect()
}

fn is_safe_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn canonical_file(path: &Path) -> Result<PathBuf, WorkspaceError> {
    let path = fs::canonicalize(absolute_path(path)?)?;
    if !path.is_file() {
        return Err(WorkspaceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("control path is not a file: {}", path.display()),
        )));
    }
    Ok(path)
}

fn external_file_path(path: &Path) -> Result<PathBuf, WorkspaceError> {
    let absolute = absolute_path(path)?;
    let file_name = absolute.file_name().ok_or_else(|| {
        WorkspaceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path has no file name: {}", absolute.display()),
        ))
    })?;
    let parent = absolute.parent().ok_or_else(|| {
        WorkspaceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path has no parent: {}", absolute.display()),
        ))
    })?;
    fs::create_dir_all(parent)?;
    Ok(fs::canonicalize(parent)?.join(file_name))
}

fn absolute_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn new_operation_id() -> String {
    let counter = OP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("workspace-{:x}-{:x}-{:x}", now_ns(), std::process::id(), counter)
}

fn now_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_ids_reject_paths() {
        assert!(is_safe_id("CHG-123_alpha.1"));
        assert!(!is_safe_id("../escape"));
        assert!(!is_safe_id("nested/path"));
        assert!(!is_safe_id(""));
    }

    #[test]
    fn generated_branch_is_stable() {
        let request = WorkspaceRequest {
            principal: "developer-ai/1".into(),
            change_id: "CHG-123".into(),
            change_plan: "plan.json".into(),
            repository_id: "oryvael".into(),
            base_ref: "main".into(),
            audit_log: "/tmp/audit.jsonl".into(),
        };
        assert_eq!(format!("oryvael/{}", request.change_id), "oryvael/CHG-123");
    }
}
