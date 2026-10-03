#![forbid(unsafe_code)]

use oryvael_approval::{
    ApprovalError, ControlPurpose, ControlSignatureBundle, ControlTrustPolicy, ControlVerification,
    verify_control,
};
use oryvael_protocol::{ChangePlan, Operation, Principal};
use oryvael_supervisor::{
    JobResult, JobSpec, NetworkMode, ResourceLimits, SupervisorError, run_job,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCatalog {
    pub version: String,
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolDefinition {
    pub id: String,
    pub executable: String,
    pub actions: BTreeMap<String, ToolAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolAction {
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub network: NetworkMode,
    #[serde(default)]
    pub read_only_paths: Vec<PathBuf>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub limits: ResourceLimits,
}

fn default_timeout_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolRole {
    Developer,
    Test,
    Security,
    Reviewer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInvocation {
    pub principal: String,
    pub role: ToolRole,
    pub change_id: String,
    pub change_plan: PathBuf,
    pub workspace: PathBuf,
    pub tool: String,
    pub action: String,
    pub audit_log: PathBuf,
    pub artifact_store: PathBuf,
}

#[derive(Debug, Error)]
pub enum ToolBrokerError {
    #[error("principal mismatch: policy is {policy}, invocation requests {invocation}")]
    PrincipalMismatch { policy: String, invocation: String },
    #[error("change id mismatch: plan is {plan}, invocation requests {invocation}")]
    ChangeIdMismatch { plan: String, invocation: String },
    #[error("developer principal must equal change-plan producer")]
    DeveloperProducerMismatch,
    #[error("independent verifier principal must differ from change-plan producer")]
    VerifierNotIndependent,
    #[error("change plan does not authorize developer tool action {0}")]
    ToolNotInRequestedCapabilities(String),
    #[error("change plan does not require verifier action {0}")]
    ToolNotInVerificationPlan(String),
    #[error("tool catalog root trust verification failed: {0}")]
    CatalogNotTrusted(String),
    #[error("unknown tool: {0}")]
    UnknownTool(String),
    #[error("unknown action {action} for tool {tool}")]
    UnknownAction { tool: String, action: String },
    #[error("control file must be outside the writable workspace: {0}")]
    ControlFileInsideWorkspace(PathBuf),
    #[error("invalid tool catalog: duplicate tool id {0}")]
    DuplicateTool(String),
    #[error("invalid tool definition: {0}")]
    InvalidTool(String),
    #[error("control signature error: {0}")]
    ControlSignature(#[from] ApprovalError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("supervisor error: {0}")]
    Supervisor(#[from] SupervisorError),
}

pub fn run_brokered_from_files(
    principal_path: impl AsRef<Path>,
    catalog_path: impl AsRef<Path>,
    catalog_trust_policy_path: impl AsRef<Path>,
    catalog_signature_bundle_path: impl AsRef<Path>,
    invocation_path: impl AsRef<Path>,
) -> Result<JobResult, ToolBrokerError> {
    let invocation_path = canonical_file(invocation_path.as_ref())?;
    let invocation_content = fs::read_to_string(&invocation_path)?;
    let invocation: ToolInvocation = serde_json::from_str(&invocation_content)?;

    let workspace = absolute_path(&invocation.workspace)?;
    fs::create_dir_all(&workspace)?;
    let workspace = fs::canonicalize(workspace)?;

    let principal_path = canonical_file(principal_path.as_ref())?;
    let catalog_path = canonical_file(catalog_path.as_ref())?;
    let catalog_trust_policy_path = canonical_file(catalog_trust_policy_path.as_ref())?;
    let catalog_signature_bundle_path = canonical_file(catalog_signature_bundle_path.as_ref())?;
    let change_plan_path = canonical_file(&invocation.change_plan)?;

    for path in [
        &principal_path,
        &catalog_path,
        &catalog_trust_policy_path,
        &catalog_signature_bundle_path,
        &invocation_path,
        &change_plan_path,
    ] {
        if path.starts_with(&workspace) {
            return Err(ToolBrokerError::ControlFileInsideWorkspace(path.clone()));
        }
    }

    let principal_content = fs::read_to_string(&principal_path)?;
    let catalog_content = fs::read_to_string(&catalog_path)?;
    let trust_policy_content = fs::read_to_string(&catalog_trust_policy_path)?;
    let signature_bundle_content = fs::read_to_string(&catalog_signature_bundle_path)?;
    let plan_content = fs::read_to_string(&change_plan_path)?;

    let catalog_hash = sha256_hex(catalog_content.as_bytes());
    let trust = verify_catalog_trust(
        &catalog_content,
        &trust_policy_content,
        &signature_bundle_content,
    )?;
    if !trust.eligible {
        let mut details = trust.reasons;
        details.extend(trust.warnings);
        return Err(ToolBrokerError::CatalogNotTrusted(details.join("; ")));
    }

    let principal: Principal = serde_json::from_str(&principal_content)?;
    let catalog: ToolCatalog = serde_json::from_str(&catalog_content)?;
    let plan: ChangePlan = serde_json::from_str(&plan_content)?;

    let hashes = InputHashes {
        principal: sha256_hex(principal_content.as_bytes()),
        catalog: catalog_hash,
        catalog_trust_policy: sha256_hex(trust_policy_content.as_bytes()),
        catalog_signature_bundle: sha256_hex(signature_bundle_content.as_bytes()),
        catalog_signature_signers: trust.valid_signers.join(","),
        invocation: sha256_hex(invocation_content.as_bytes()),
        change_plan: sha256_hex(plan_content.as_bytes()),
    };

    let job = resolve_job(&principal, &catalog, &plan, &invocation, hashes)?;
    Ok(run_job(principal, job)?)
}

fn verify_catalog_trust(
    catalog_content: &str,
    trust_policy_content: &str,
    signature_bundle_content: &str,
) -> Result<ControlVerification, ToolBrokerError> {
    let policy: ControlTrustPolicy = serde_json::from_str(trust_policy_content)?;
    let bundle: ControlSignatureBundle = serde_json::from_str(signature_bundle_content)?;
    let catalog_hash = sha256_hex(catalog_content.as_bytes());
    Ok(verify_control(
        &policy,
        &bundle,
        ControlPurpose::ToolCatalog,
        &catalog_hash,
    )?)
}

#[derive(Debug, Clone)]
struct InputHashes {
    principal: String,
    catalog: String,
    catalog_trust_policy: String,
    catalog_signature_bundle: String,
    catalog_signature_signers: String,
    invocation: String,
    change_plan: String,
}

fn resolve_job(
    principal: &Principal,
    catalog: &ToolCatalog,
    plan: &ChangePlan,
    invocation: &ToolInvocation,
    hashes: InputHashes,
) -> Result<JobSpec, ToolBrokerError> {
    validate_catalog(catalog)?;

    if principal.principal != invocation.principal {
        return Err(ToolBrokerError::PrincipalMismatch {
            policy: principal.principal.clone(),
            invocation: invocation.principal.clone(),
        });
    }

    if plan.id != invocation.change_id {
        return Err(ToolBrokerError::ChangeIdMismatch {
            plan: plan.id.clone(),
            invocation: invocation.change_id.clone(),
        });
    }

    let action_id = format!("{}.{}", invocation.tool, invocation.action);
    match invocation.role {
        ToolRole::Developer => {
            if plan.producer != principal.principal {
                return Err(ToolBrokerError::DeveloperProducerMismatch);
            }
            let requested = format!("tool:{action_id}");
            if !plan
                .requested_capabilities
                .iter()
                .any(|item| item == &requested)
            {
                return Err(ToolBrokerError::ToolNotInRequestedCapabilities(requested));
            }
        }
        ToolRole::Test | ToolRole::Security | ToolRole::Reviewer => {
            if plan.producer == principal.principal {
                return Err(ToolBrokerError::VerifierNotIndependent);
            }
            if !plan.verification.iter().any(|item| item == &action_id) {
                return Err(ToolBrokerError::ToolNotInVerificationPlan(action_id));
            }
        }
    }

    let tool = catalog
        .tools
        .iter()
        .find(|tool| tool.id == invocation.tool)
        .ok_or_else(|| ToolBrokerError::UnknownTool(invocation.tool.clone()))?;

    let action =
        tool.actions
            .get(&invocation.action)
            .ok_or_else(|| ToolBrokerError::UnknownAction {
                tool: invocation.tool.clone(),
                action: invocation.action.clone(),
            })?;

    if tool.executable.trim().is_empty() || !tool.executable.starts_with('/') {
        return Err(ToolBrokerError::InvalidTool(format!(
            "{} executable must be an absolute path",
            tool.id
        )));
    }
    if action.timeout_seconds == 0 {
        return Err(ToolBrokerError::InvalidTool(format!(
            "{}.{}, timeout must be greater than zero",
            tool.id, invocation.action
        )));
    }

    let mut command = Vec::with_capacity(action.argv.len() + 1);
    command.push(tool.executable.clone());
    command.extend(action.argv.iter().cloned());

    let mut audit_context = BTreeMap::new();
    audit_context.insert("broker".into(), "oryvael-tool-broker".into());
    audit_context.insert("tool".into(), invocation.tool.clone());
    audit_context.insert("tool_action".into(), invocation.action.clone());
    audit_context.insert("tool_role".into(), role_name(invocation.role).into());
    audit_context.insert("change_plan_sha256".into(), hashes.change_plan);
    audit_context.insert("tool_catalog_sha256".into(), hashes.catalog);
    audit_context.insert(
        "tool_catalog_trust_policy_sha256".into(),
        hashes.catalog_trust_policy,
    );
    audit_context.insert(
        "tool_catalog_signature_bundle_sha256".into(),
        hashes.catalog_signature_bundle,
    );
    audit_context.insert(
        "tool_catalog_signature_verified".into(),
        "true".into(),
    );
    audit_context.insert(
        "tool_catalog_signature_signers".into(),
        hashes.catalog_signature_signers,
    );
    audit_context.insert("tool_invocation_sha256".into(), hashes.invocation);
    audit_context.insert("principal_policy_sha256".into(), hashes.principal);

    Ok(JobSpec {
        principal: principal.principal.clone(),
        change_id: plan.id.clone(),
        workspace: invocation.workspace.clone(),
        command,
        network: action.network,
        read_only_paths: action.read_only_paths.clone(),
        timeout_seconds: action.timeout_seconds,
        limits: action.limits.clone(),
        required_operations: vec![Operation {
            resource: "tool".into(),
            action: "execute".into(),
            target: Some(action_id),
        }],
        audit_context,
        audit_log: invocation.audit_log.clone(),
        artifact_store: invocation.artifact_store.clone(),
    })
}

fn validate_catalog(catalog: &ToolCatalog) -> Result<(), ToolBrokerError> {
    let mut ids = BTreeSet::new();
    for tool in &catalog.tools {
        if tool.id.trim().is_empty() {
            return Err(ToolBrokerError::InvalidTool(
                "tool id must not be empty".into(),
            ));
        }
        if !ids.insert(tool.id.as_str()) {
            return Err(ToolBrokerError::DuplicateTool(tool.id.clone()));
        }
        if tool.actions.is_empty() {
            return Err(ToolBrokerError::InvalidTool(format!(
                "{} must declare at least one action",
                tool.id
            )));
        }
    }
    Ok(())
}

fn canonical_file(path: &Path) -> Result<PathBuf, ToolBrokerError> {
    let path = fs::canonicalize(absolute_path(path)?)?;
    if !path.is_file() {
        return Err(ToolBrokerError::InvalidTool(format!(
            "control path is not a file: {}",
            path.display()
        )));
    }
    Ok(path)
}

fn absolute_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn role_name(role: ToolRole) -> &'static str {
    match role {
        ToolRole::Developer => "developer",
        ToolRole::Test => "test",
        ToolRole::Security => "security",
        ToolRole::Reviewer => "reviewer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryvael_protocol::{CapabilityGrant, ChangeClass, PrincipalKind};

    fn principal(id: &str) -> Principal {
        Principal {
            principal: id.into(),
            kind: PrincipalKind::AiAgent,
            grants: Vec::<CapabilityGrant>::new(),
        }
    }

    fn catalog() -> ToolCatalog {
        let mut actions = BTreeMap::new();
        actions.insert(
            "syntax-check".into(),
            ToolAction {
                argv: vec![
                    "-m".into(),
                    "py_compile".into(),
                    "/workspace/src/demo.py".into(),
                ],
                network: NetworkMode::Deny,
                read_only_paths: vec![],
                timeout_seconds: 10,
                limits: ResourceLimits::default(),
            },
        );

        ToolCatalog {
            version: "1".into(),
            tools: vec![ToolDefinition {
                id: "python".into(),
                executable: "/usr/bin/python3".into(),
                actions,
            }],
        }
    }

    fn plan() -> ChangePlan {
        ChangePlan {
            id: "CHG-TOOL-1".into(),
            intent: "validate broker".into(),
            change_class: ChangeClass::C1,
            producer: "developer-ai/demo".into(),
            components: vec!["demo".into()],
            paths: vec!["src/demo.py".into()],
            requested_capabilities: vec!["tool:python.syntax-check".into()],
            dependencies_added: vec![],
            verification: vec!["python.syntax-check".into()],
            max_rollout_ring: Some("none".into()),
            rollback: "delete workspace".into(),
        }
    }

    fn invocation(role: ToolRole, principal: &str) -> ToolInvocation {
        ToolInvocation {
            principal: principal.into(),
            role,
            change_id: "CHG-TOOL-1".into(),
            change_plan: "plan.json".into(),
            workspace: "/tmp/workspace".into(),
            tool: "python".into(),
            action: "syntax-check".into(),
            audit_log: "/tmp/audit.jsonl".into(),
            artifact_store: "/tmp/artifacts".into(),
        }
    }

    fn hashes() -> InputHashes {
        InputHashes {
            principal: "a".repeat(64),
            catalog: "b".repeat(64),
            catalog_trust_policy: "c".repeat(64),
            catalog_signature_bundle: "d".repeat(64),
            catalog_signature_signers: "root/catalog".into(),
            invocation: "e".repeat(64),
            change_plan: "f".repeat(64),
        }
    }

    #[test]
    fn developer_action_is_bound_to_plan() {
        let principal = principal("developer-ai/demo");
        let job = resolve_job(
            &principal,
            &catalog(),
            &plan(),
            &invocation(ToolRole::Developer, "developer-ai/demo"),
            hashes(),
        )
        .unwrap();

        assert_eq!(job.command[0], "/usr/bin/python3");
        assert_eq!(
            job.required_operations[0].target.as_deref(),
            Some("python.syntax-check")
        );
        assert_eq!(
            job.audit_context.get("change_plan_sha256"),
            Some(&"f".repeat(64))
        );
        assert_eq!(
            job.audit_context
                .get("tool_catalog_signature_verified")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn developer_cannot_invoke_unplanned_action() {
        let principal = principal("developer-ai/demo");
        let mut plan = plan();
        plan.requested_capabilities.clear();

        assert!(matches!(
            resolve_job(
                &principal,
                &catalog(),
                &plan,
                &invocation(ToolRole::Developer, "developer-ai/demo"),
                hashes()
            ),
            Err(ToolBrokerError::ToolNotInRequestedCapabilities(_))
        ));
    }

    #[test]
    fn verifier_must_be_independent() {
        let principal = principal("developer-ai/demo");

        assert!(matches!(
            resolve_job(
                &principal,
                &catalog(),
                &plan(),
                &invocation(ToolRole::Test, "developer-ai/demo"),
                hashes()
            ),
            Err(ToolBrokerError::VerifierNotIndependent)
        ));
    }

    #[test]
    fn committed_catalog_signature_is_valid_and_byte_bound() {
        let catalog = include_str!("../../../examples/tool-broker/catalog.json");
        let policy = include_str!("../../../examples/tool-broker/catalog-trust-policy.json");
        let bundle = include_str!("../../../examples/tool-broker/catalog-signatures.json");

        let verified = verify_catalog_trust(catalog, policy, bundle).unwrap();
        assert!(verified.eligible);
        assert_eq!(verified.valid_signers, vec!["test-root/tool-catalog"]);

        let mut mutated = catalog.to_owned();
        mutated.push(' ');
        assert!(!verify_catalog_trust(&mutated, policy, bundle)
            .unwrap()
            .eligible);
    }
}
