#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
