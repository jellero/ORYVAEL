#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    AiAgent,
    Service,
    Application,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub effect: Effect,
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub delegable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    pub principal: String,
    pub kind: PrincipalKind,
    #[serde(default)]
    pub grants: Vec<CapabilityGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Operation {
    pub resource: String,
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeClass {
    C0,
    C1,
    C2,
    C3,
    C4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangePlan {
    pub id: String,
    pub intent: String,
    #[serde(rename = "class")]
    pub change_class: ChangeClass,
    pub producer: String,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    #[serde(default)]
    pub dependencies_added: Vec<String>,
    #[serde(default)]
    pub verification: Vec<String>,
    #[serde(default)]
    pub max_rollout_ring: Option<String>,
    pub rollback: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allowed,
    Denied,
    Observed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub timestamp_ns: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub decision: AuditDecision,
    #[serde(default)]
    pub change_id: Option<String>,
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadArtifactFormat {
    OryvaelNative,
    Oci,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadArtifact {
    pub format: WorkloadArtifactFormat,
    pub reference: String,
    pub digest: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadIsolation {
    Process,
    Microvm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadResources {
    pub memory_bytes: u64,
    pub cpu_millis_per_second: u32,
    pub max_processes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadNetworkDefault {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadNetwork {
    pub default: WorkloadNetworkDefault,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadCapability {
    pub resource: String,
    pub actions: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub user_presence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadVolumeAccess {
    Read,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadVolume {
    pub id: String,
    pub target: String,
    pub access: WorkloadVolumeAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadSecret {
    pub id: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadManifest {
    pub version: String,
    pub id: String,
    pub artifact: WorkloadArtifact,
    pub isolation: WorkloadIsolation,
    pub entrypoint: Vec<String>,
    pub resources: WorkloadResources,
    pub network: WorkloadNetwork,
    #[serde(default)]
    pub capabilities: Vec<WorkloadCapability>,
    #[serde(default)]
    pub volumes: Vec<WorkloadVolume>,
    #[serde(default)]
    pub secrets: Vec<WorkloadSecret>,
}

pub fn validate_workload_manifest(manifest: &WorkloadManifest) -> Vec<String> {
    let mut violations = Vec::new();

    if manifest.version != "oryvael-workload/1" {
        violations.push("unsupported workload manifest version".to_string());
    }
    if manifest.id.is_empty()
        || !manifest.id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        violations.push(
            "workload id must use lowercase ASCII letters, digits, '.', '_' or '-'".to_string(),
        );
    }
    if manifest.artifact.reference.is_empty() {
        violations.push("artifact reference must not be empty".to_string());
    }
    if !valid_sha256_digest(&manifest.artifact.digest) {
        violations.push("artifact digest must be sha256:<64 lowercase hex characters>".to_string());
    }
    if !matches!(
        manifest.artifact.platform.as_str(),
        "oryvael/x86_64" | "oryvael/aarch64" | "linux/x86_64" | "linux/aarch64"
    ) {
        violations.push("unsupported workload platform".to_string());
    }
    if manifest.entrypoint.is_empty() || manifest.entrypoint[0].is_empty() {
        violations.push("workload entrypoint must contain an executable".to_string());
    }
    if manifest.resources.memory_bytes < 1024 * 1024 {
        violations.push("workload memory budget must be at least 1 MiB".to_string());
    }
    if !(1..=1000).contains(&manifest.resources.cpu_millis_per_second) {
        violations.push("cpu_millis_per_second must be between 1 and 1000".to_string());
    }
    if !(1..=4096).contains(&manifest.resources.max_processes) {
        violations.push("max_processes must be between 1 and 4096".to_string());
    }
    if manifest.network.default != WorkloadNetworkDefault::Deny {
        violations.push("workload network policy must default to deny".to_string());
    }

    let mut capability_keys = BTreeSet::new();
    for capability in &manifest.capabilities {
        if capability.resource.is_empty() {
            violations.push("capability resource must not be empty".to_string());
            continue;
        }
        if capability.resource == "*" || capability.actions.iter().any(|action| action == "*") {
            violations.push(format!(
                "workload {} requests wildcard authority",
                manifest.id
            ));
        }
        if reserved_workload_authority(&capability.resource, &capability.actions) {
            violations.push(format!(
                "workload {} requests reserved authority {}",
                manifest.id, capability.resource
            ));
        }
        if capability.actions.is_empty() || capability.actions.iter().any(String::is_empty) {
            violations.push(format!(
                "capability {} must declare at least one non-empty action",
                capability.resource
            ));
        }

        let key = (
            capability.resource.clone(),
            capability.scope.clone().unwrap_or_default(),
        );
        if !capability_keys.insert(key) {
            violations.push(format!(
                "duplicate capability scope for {}",
                capability.resource
            ));
        }
    }

    for volume in &manifest.volumes {
        if volume.id.is_empty() || !volume.target.starts_with('/') {
            violations
                .push("workload volumes require a non-empty id and absolute target".to_string());
        }
    }

    for secret in &manifest.secrets {
        if secret.id.is_empty() || secret.operations.is_empty() {
            violations
                .push("workload secrets require an id and at least one operation".to_string());
        }
        if secret
            .operations
            .iter()
            .any(|operation| !matches!(operation.as_str(), "sign" | "decrypt"))
        {
            violations.push(format!(
                "secret {} requests an unsupported raw secret operation",
                secret.id
            ));
        }
    }

    violations
}

fn valid_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn reserved_workload_authority(resource: &str, actions: &[String]) -> bool {
    let protected_prefixes = ["root", "policy", "kernel", "capability"];
    if protected_prefixes.iter().any(|prefix| {
        resource == *prefix
            || resource.starts_with(&format!("{prefix}."))
            || resource.starts_with(&format!("{prefix}:"))
    }) {
        return true;
    }

    resource.starts_with("audit")
        && actions
            .iter()
            .any(|action| matches!(action.as_str(), "delete" | "disable" | "rewrite"))
}

#[cfg(test)]
mod workload_tests {
    use super::*;

    fn manifest() -> WorkloadManifest {
        WorkloadManifest {
            version: "oryvael-workload/1".to_string(),
            id: "example.web".to_string(),
            artifact: WorkloadArtifact {
                format: WorkloadArtifactFormat::Oci,
                reference: "oci://registry.example/oryvael/web".to_string(),
                digest: format!("sha256:{}", "a".repeat(64)),
                platform: "oryvael/x86_64".to_string(),
            },
            isolation: WorkloadIsolation::Process,
            entrypoint: vec!["/app/web".to_string()],
            resources: WorkloadResources {
                memory_bytes: 256 * 1024 * 1024,
                cpu_millis_per_second: 250,
                max_processes: 8,
            },
            network: WorkloadNetwork {
                default: WorkloadNetworkDefault::Deny,
            },
            capabilities: vec![WorkloadCapability {
                resource: "socket:tcp/8080".to_string(),
                actions: vec!["listen".to_string(), "accept".to_string()],
                scope: None,
                user_presence: false,
            }],
            volumes: Vec::new(),
            secrets: vec![WorkloadSecret {
                id: "tls-web".to_string(),
                operations: vec!["sign".to_string()],
            }],
        }
    }

    #[test]
    fn accepts_scoped_workload() {
        assert!(validate_workload_manifest(&manifest()).is_empty());
    }

    #[test]
    fn rejects_wildcard_authority() {
        let mut candidate = manifest();
        candidate.capabilities[0].actions = vec!["*".to_string()];
        assert!(
            validate_workload_manifest(&candidate)
                .iter()
                .any(|violation| violation.contains("wildcard authority"))
        );
    }

    #[test]
    fn rejects_reserved_policy_authority() {
        let mut candidate = manifest();
        candidate.capabilities[0].resource = "policy.modify".to_string();
        assert!(
            validate_workload_manifest(&candidate)
                .iter()
                .any(|violation| violation.contains("reserved authority"))
        );
    }

    #[test]
    fn rejects_network_allow_default() {
        let mut candidate = manifest();
        candidate.network.default = WorkloadNetworkDefault::Allow;
        assert!(
            validate_workload_manifest(&candidate)
                .iter()
                .any(|violation| violation.contains("default to deny"))
        );
    }
}
