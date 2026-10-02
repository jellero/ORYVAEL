#![forbid(unsafe_code)]

use oryvael_protocol::AuditEvent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: AuditEvent,
    pub hash: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AuditLedger {
    records: Vec<AuditRecord>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("sequence mismatch at record {index}: expected {expected}, got {actual}")]
    Sequence {
        index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("previous hash mismatch at record {index}")]
    PreviousHash { index: usize },
    #[error("record hash mismatch at record {index}")]
    Hash { index: usize },
    #[error("event serialization failed: {0}")]
    Serialization(String),
}

impl AuditLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_records(records: Vec<AuditRecord>) -> Self {
        Self { records }
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn append(&mut self, event: AuditEvent) -> Result<&AuditRecord, AuditError> {
        let sequence = self.records.len() as u64;
        let previous_hash = self
            .records
            .last()
            .map(|record| record.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_owned());

        let hash = compute_hash(sequence, &previous_hash, &event)?;
        self.records.push(AuditRecord {
            sequence,
            previous_hash,
            event,
            hash,
        });
        Ok(self.records.last().expect("record was just appended"))
    }

    pub fn verify(&self) -> Result<(), AuditError> {
        let mut expected_previous = GENESIS_HASH.to_owned();

        for (index, record) in self.records.iter().enumerate() {
            let expected_sequence = index as u64;
            if record.sequence != expected_sequence {
                return Err(AuditError::Sequence {
                    index,
                    expected: expected_sequence,
                    actual: record.sequence,
                });
            }

            if record.previous_hash != expected_previous {
                return Err(AuditError::PreviousHash { index });
            }

            let expected_hash =
                compute_hash(record.sequence, &record.previous_hash, &record.event)?;
            if record.hash != expected_hash {
                return Err(AuditError::Hash { index });
            }

            expected_previous = record.hash.clone();
        }

        Ok(())
    }
}

fn compute_hash(
    sequence: u64,
    previous_hash: &str,
    event: &AuditEvent,
) -> Result<String, AuditError> {
    let payload =
        serde_json::to_vec(event).map_err(|error| AuditError::Serialization(error.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update(payload);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryvael_protocol::AuditDecision;
    use std::collections::BTreeMap;

    fn event(action: &str) -> AuditEvent {
        AuditEvent {
            timestamp_ns: 1,
            actor: "developer-ai/test".into(),
            action: action.into(),
            target: "workspace".into(),
            decision: AuditDecision::Allowed,
            change_id: Some("CHG-1".into()),
            operation_id: Some("OP-1".into()),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn valid_chain_verifies() {
        let mut ledger = AuditLedger::new();
        ledger.append(event("read")).unwrap();
        ledger.append(event("write")).unwrap();
        assert_eq!(ledger.verify(), Ok(()));
    }

    #[test]
    fn tampering_is_detected() {
        let mut ledger = AuditLedger::new();
        ledger.append(event("read")).unwrap();

        let mut records = ledger.records().to_vec();
        records[0].event.action = "modified".into();

        let tampered = AuditLedger::from_records(records);
        assert!(matches!(tampered.verify(), Err(AuditError::Hash { .. })));
    }
}
