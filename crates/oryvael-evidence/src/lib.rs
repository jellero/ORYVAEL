#![forbid(unsafe_code)]

use oryvael_audit::{AuditError, AuditRecord, load_jsonl};
use oryvael_protocol::AuditDecision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedEvidence {
    pub change_id: String,
    pub change_plan_sha256: String,
    pub name: String,
    pub principal: String,
    pub role: String,
    pub status: EvidenceStatus,
    pub evidence_hash: String,
    pub operation_id: String,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("operation not found: {0}")]
    OperationNotFound(String),
    #[error("invalid broker evidence: {0}")]
    Invalid(String),
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn extract_from_jsonl(
    audit_path: impl AsRef<Path>,
    operation_id: &str,
) -> Result<VerifiedEvidence, EvidenceError> {
    if operation_id.trim().is_empty() {
        return Err(EvidenceError::Invalid("operation_id is empty".into()));
    }

    let ledger = load_jsonl(audit_path)?;
    let records = ledger
        .records()
        .iter()
        .filter(|record| record.event.operation_id.as_deref() == Some(operation_id))
        .cloned()
        .collect::<Vec<_>>();

    if records.is_empty() {
        return Err(EvidenceError::OperationNotFound(operation_id.into()));
    }

    let requests = records
        .iter()
        .filter(|record| record.event.action == "supervisor.run.request")
        .collect::<Vec<_>>();
    if requests.len() != 1 {
        return Err(EvidenceError::Invalid(format!(
            "expected one supervisor.run.request, found {}",
            requests.len()
        )));
    }
    let request = requests[0];

    let broker = metadata(request, "context.broker")?;
    if broker != "oryvael-tool-broker" {
        return Err(EvidenceError::Invalid(format!(
            "unsupported evidence producer: {broker}"
        )));
    }

    let tool = metadata(request, "context.tool")?;
    let action = metadata(request, "context.tool_action")?;
    let role = metadata(request, "context.tool_role")?;
    if !matches!(role, "test" | "security" | "reviewer") {
        return Err(EvidenceError::Invalid(format!(
            "tool role {role} is not a verifier role"
        )));
    }

    let change_plan_sha256 = metadata(request, "context.change_plan_sha256")?.to_owned();
    if !is_sha256(&change_plan_sha256) {
        return Err(EvidenceError::Invalid(
            "change plan hash is not SHA-256".into(),
        ));
    }

    let change_id = request
        .event
        .change_id
        .clone()
        .ok_or_else(|| EvidenceError::Invalid("run request has no change_id".into()))?;
    let principal = request.event.actor.clone();
    let name = format!("{tool}.{action}");

    if records.iter().any(|record| record.event.actor != principal) {
        return Err(EvidenceError::Invalid(
            "operation contains multiple actor identities".into(),
        ));
    }

    let tool_allows = records
        .iter()
        .filter(|record| {
            record.event.action == "policy.evaluate"
                && record.event.decision == AuditDecision::Allowed
                && record.event.target == name
                && record.event.metadata.get("resource").map(String::as_str) == Some("tool")
                && record.event.metadata.get("action").map(String::as_str) == Some("execute")
        })
        .count();

    if tool_allows != 1 {
        return Err(EvidenceError::Invalid(format!(
            "expected one allowed tool.execute decision, found {tool_allows}"
        )));
    }

    let exits = records
        .iter()
        .filter(|record| record.event.action == "supervisor.sandbox.exit")
        .collect::<Vec<_>>();
    if exits.len() != 1 {
        return Err(EvidenceError::Invalid(format!(
            "expected one supervisor.sandbox.exit, found {}",
            exits.len()
        )));
    }
    let exit = exits[0];

    let exit_code = metadata(exit, "exit_code")?;
    let timed_out = metadata(exit, "timed_out")?;

    let status = if exit.event.decision == AuditDecision::Observed
        && exit_code == "0"
        && timed_out == "false"
    {
        EvidenceStatus::Pass
    } else if exit.event.decision == AuditDecision::Failed {
        EvidenceStatus::Fail
    } else {
        return Err(EvidenceError::Invalid(format!(
            "inconsistent exit state: decision={:?}, exit_code={exit_code}, timed_out={timed_out}",
            exit.event.decision
        )));
    };

    let evidence_hash = hash_records(&records)?;

    Ok(VerifiedEvidence {
        change_id,
        change_plan_sha256,
        name,
        principal,
        role: role.to_owned(),
        status,
        evidence_hash,
        operation_id: operation_id.into(),
    })
}

fn metadata<'a>(record: &'a AuditRecord, key: &str) -> Result<&'a str, EvidenceError> {
    record
        .event
        .metadata
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| EvidenceError::Invalid(format!("missing audit metadata key {key}")))
}

fn hash_records(records: &[AuditRecord]) -> Result<String, EvidenceError> {
    let encoded = serde_json::to_vec(records)?;
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryvael_audit::AuditLedger;
    use oryvael_protocol::{AuditDecision, AuditEvent};
    use std::collections::BTreeMap;

    fn event(
        action: &str,
        decision: AuditDecision,
        target: &str,
        metadata: BTreeMap<String, String>,
    ) -> AuditEvent {
        AuditEvent {
            timestamp_ns: 1,
            actor: "test-ai/example".into(),
            action: action.into(),
            target: target.into(),
            decision,
            change_id: Some("CHG-1".into()),
            operation_id: Some("op-1".into()),
            metadata,
        }
    }

    #[test]
    fn evidence_hash_changes_with_records() {
        let mut ledger = AuditLedger::new();
        ledger
            .append(event(
                "supervisor.run.request",
                AuditDecision::Observed,
                "/workspace",
                BTreeMap::new(),
            ))
            .unwrap();

        let first = hash_records(ledger.records()).unwrap();

        ledger
            .append(event(
                "supervisor.sandbox.exit",
                AuditDecision::Observed,
                "/usr/bin/true",
                BTreeMap::new(),
            ))
            .unwrap();

        let second = hash_records(ledger.records()).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn sha256_shape_is_strict() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"g".repeat(64)));
        assert!(!is_sha256(&"a".repeat(63)));
    }
}
