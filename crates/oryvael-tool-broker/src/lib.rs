#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

const CATALOG_SIGNATURE_DOMAIN: &[u8] = b"ORYVAEL-TOOL-CATALOG-V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolCatalog {
    pub version: String,
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    pub id: String,
    pub executable: String,
    pub actions: BTreeMap<String, ToolAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogTrustPolicy {
    pub version: u32,
    #[serde(default)]
    pub signers: Vec<CatalogTrustedSigner>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogTrustedSigner {
    pub id: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogSignature {
    pub version: u32,
    pub signer_id: String,
    pub catalog_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone)]
struct VerifiedCatalogControl {
    signer_id: String,
    trust_policy_sha256: String,
    signature_sha256: String,
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
    #[error("catalog trust policy version {0} is unsupported")]
    UnsupportedCatalogTrustVersion(u32),
    #[error("catalog signature version {0} is unsupported")]
    UnsupportedCatalogSignatureVersion(u32),
    #[error("catalog signer is not trusted: {0}")]
    UntrustedCatalogSigner(String),
    #[error("catalog signer public key is invalid: {0}")]
    InvalidCatalogPublicKey(String),
    #[error("catalog signature has invalid length for signer {0}")]
    InvalidCatalogSignatureLength(String),
    #[error("catalog hash mismatch: signature binds {signed}, actual catalog is {actual}")]
    CatalogHashMismatch { signed: String, actual: String },
    #[error("catalog signature verification failed for signer {0}")]
    CatalogSignatureInvalid(String),
    #[error("catalog trust policy contains duplicate signer id {0}")]
    DuplicateCatalogSigner(String),
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
    let trust_policy_path = canonical_file(&catalog_sidecar_path(&catalog_path, "trust"))?;
    let signature_path = canonical_file(&catalog_sidecar_path(&catalog_path, "signature"))?;
    let change_plan_path = canonical_file(&invocation.change_plan)?;

    for path in [
        &principal_path,
        &catalog_path,
        &trust_policy_path,
        &signature_path,
        &invocation_path,
        &change_plan_path,
    ] {
        if path.starts_with(&workspace) {
            return Err(ToolBrokerError::ControlFileInsideWorkspace(path.clone()));
        }
    }

    let principal_content = fs::read_to_string(&principal_path)?;
    let catalog_content = fs::read_to_string(&catalog_path)?;
    let trust_policy_content = fs::read_to_string(&trust_policy_path)?;
    let signature_content = fs::read_to_string(&signature_path)?;
    let plan_content = fs::read_to_string(&change_plan_path)?;

    let principal: Principal = serde_json::from_str(&principal_content)?;
    let catalog: ToolCatalog = serde_json::from_str(&catalog_content)?;
    let trust_policy: CatalogTrustPolicy = serde_json::from_str(&trust_policy_content)?;
    let signature: CatalogSignature = serde_json::from_str(&signature_content)?;
    let plan: ChangePlan = serde_json::from_str(&plan_content)?;

    let catalog_control = verify_catalog_signature(
        catalog_content.as_bytes(),
        trust_policy_content.as_bytes(),
        signature_content.as_bytes(),
        &trust_policy,
        &signature,
    )?;

    let hashes = InputHashes {
        principal: sha256_hex(principal_content.as_bytes()),
        catalog: sha256_hex(catalog_content.as_bytes()),
        invocation: sha256_hex(invocation_content.as_bytes()),
        change_plan: sha256_hex(plan_content.as_bytes()),
    };

    let job = resolve_job(
        &principal,
        &catalog,
        &plan,
        &invocation,
        hashes,
        catalog_control,
    )?;
    Ok(run_job(principal, job)?)
}

#[derive(Debug, Clone)]
struct InputHashes {
    principal: String,
    catalog: String,
    invocation: String,
    change_plan: String,
}

fn resolve_job(
    principal: &Principal,
    catalog: &ToolCatalog,
    plan: &ChangePlan,
    invocation: &ToolInvocation,
    hashes: InputHashes,
    catalog_control: VerifiedCatalogControl,
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
    audit_context.insert("tool_catalog_signer".into(), catalog_control.signer_id);
    audit_context.insert(
        "tool_catalog_trust_policy_sha256".into(),
        catalog_control.trust_policy_sha256,
    );
    audit_context.insert(
        "tool_catalog_signature_sha256".into(),
        catalog_control.signature_sha256,
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

fn verify_catalog_signature(
    catalog_bytes: &[u8],
    trust_policy_bytes: &[u8],
    signature_bytes: &[u8],
    policy: &CatalogTrustPolicy,
    statement: &CatalogSignature,
) -> Result<VerifiedCatalogControl, ToolBrokerError> {
    if policy.version != 1 {
        return Err(ToolBrokerError::UnsupportedCatalogTrustVersion(
            policy.version,
        ));
    }
    if statement.version != 1 {
        return Err(ToolBrokerError::UnsupportedCatalogSignatureVersion(
            statement.version,
        ));
    }

    let mut signer_ids = BTreeSet::new();
    for signer in &policy.signers {
        if !signer_ids.insert(signer.id.as_str()) {
            return Err(ToolBrokerError::DuplicateCatalogSigner(signer.id.clone()));
        }
    }

    let actual_hash = sha256_hex(catalog_bytes);
    if statement.catalog_sha256 != actual_hash {
        return Err(ToolBrokerError::CatalogHashMismatch {
            signed: statement.catalog_sha256.clone(),
            actual: actual_hash,
        });
    }

    let signer = policy
        .signers
        .iter()
        .find(|signer| signer.id == statement.signer_id)
        .ok_or_else(|| ToolBrokerError::UntrustedCatalogSigner(statement.signer_id.clone()))?;

    let public_bytes = decode_fixed::<32>(&signer.public_key_hex)
        .map_err(|_| ToolBrokerError::InvalidCatalogPublicKey(signer.id.clone()))?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| ToolBrokerError::InvalidCatalogPublicKey(signer.id.clone()))?;
    let signature_raw = decode_fixed::<64>(&statement.signature_hex)
        .map_err(|_| ToolBrokerError::InvalidCatalogSignatureLength(signer.id.clone()))?;
    let signature = Signature::from_bytes(&signature_raw);
    let payload = catalog_signature_payload(&statement.signer_id, &statement.catalog_sha256);

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| ToolBrokerError::CatalogSignatureInvalid(signer.id.clone()))?;

    Ok(VerifiedCatalogControl {
        signer_id: signer.id.clone(),
        trust_policy_sha256: sha256_hex(trust_policy_bytes),
        signature_sha256: sha256_hex(signature_bytes),
    })
}

fn catalog_signature_payload(signer_id: &str, catalog_sha256: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        CATALOG_SIGNATURE_DOMAIN.len() + signer_id.len() + catalog_sha256.len() + 2,
    );
    payload.extend_from_slice(CATALOG_SIGNATURE_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(signer_id.as_bytes());
    payload.push(0);
    payload.extend_from_slice(catalog_sha256.as_bytes());
    payload
}

fn catalog_sidecar_path(catalog_path: &Path, kind: &str) -> PathBuf {
    let stem = catalog_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("catalog");
    catalog_path.with_file_name(format!("{stem}.{kind}.json"))
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let decoded = hex::decode(value)?;
    decoded
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
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
    use ed25519_dalek::{Signer, SigningKey};
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
            invocation: "c".repeat(64),
            change_plan: "d".repeat(64),
        }
    }

    fn catalog_control() -> VerifiedCatalogControl {
        VerifiedCatalogControl {
            signer_id: "root/test".into(),
            trust_policy_sha256: "e".repeat(64),
            signature_sha256: "f".repeat(64),
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
            catalog_control(),
        )
        .unwrap();

        assert_eq!(job.command[0], "/usr/bin/python3");
        assert_eq!(
            job.required_operations[0].target.as_deref(),
            Some("python.syntax-check")
        );
        assert_eq!(
            job.audit_context.get("change_plan_sha256"),
            Some(&"d".repeat(64))
        );
        assert_eq!(
            job.audit_context
                .get("tool_catalog_signer")
                .map(String::as_str),
            Some("root/test")
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
                hashes(),
                catalog_control(),
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
                hashes(),
                catalog_control(),
            ),
            Err(ToolBrokerError::VerifierNotIndependent)
        ));
    }

    #[test]
    fn signed_catalog_verifies_and_tampering_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let signer_id = "root/test";
        let catalog_bytes = b"{\"version\":\"1\",\"tools\":[]}";
        let catalog_hash = sha256_hex(catalog_bytes);
        let signature = signing_key.sign(&catalog_signature_payload(signer_id, &catalog_hash));

        let policy = CatalogTrustPolicy {
            version: 1,
            signers: vec![CatalogTrustedSigner {
                id: signer_id.into(),
                public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            }],
        };
        let statement = CatalogSignature {
            version: 1,
            signer_id: signer_id.into(),
            catalog_sha256: catalog_hash,
            signature_hex: hex::encode(signature.to_bytes()),
        };
        let policy_bytes = serde_json::to_vec(&policy).unwrap();
        let statement_bytes = serde_json::to_vec(&statement).unwrap();

        assert!(
            verify_catalog_signature(
                catalog_bytes,
                &policy_bytes,
                &statement_bytes,
                &policy,
                &statement,
            )
            .is_ok()
        );

        assert!(matches!(
            verify_catalog_signature(
                b"tampered",
                &policy_bytes,
                &statement_bytes,
                &policy,
                &statement,
            ),
            Err(ToolBrokerError::CatalogHashMismatch { .. })
        ));
    }
}
