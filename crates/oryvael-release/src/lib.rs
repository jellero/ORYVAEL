#![forbid(unsafe_code)]

use oryvael_proof::{ProofError, ProofPackage, build_audited_from_files};
use oryvael_protocol::{ChangeClass, ChangePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RolloutRing {
    None,
    Simulator,
    Developer,
    Canary,
    Fleet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseGateDecision {
    pub change_id: String,
    pub change_class: ChangeClass,
    pub requested_ring: RolloutRing,
    pub maximum_ring: RolloutRing,
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub proof_sha256: String,
    pub evidence_verified: bool,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid rollout ring: {0}")]
    InvalidRing(String),
    #[error("artifact is not a file: {0}")]
    InvalidArtifact(String),
}

pub fn check_from_files(
    plan_path: impl AsRef<Path>,
    audited_input_path: impl AsRef<Path>,
    artifact_name: &str,
    artifact_path: impl AsRef<Path>,
    requested_ring: &str,
) -> Result<ReleaseGateDecision, ReleaseError> {
    let plan_content = fs::read_to_string(plan_path.as_ref())?;
    let plan: ChangePlan = serde_json::from_str(&plan_content)?;
    let proof = build_audited_from_files(plan_path, audited_input_path)?;
    let artifact_path = artifact_path.as_ref();

    if !artifact_path.is_file() {
        return Err(ReleaseError::InvalidArtifact(
            artifact_path.display().to_string(),
        ));
    }

    let requested_ring = parse_ring(requested_ring)?;
    let maximum_ring = match plan.max_rollout_ring.as_deref() {
        Some(ring) => parse_ring(ring)?,
        None => RolloutRing::None,
    };

    Ok(check(
        &plan,
        &proof,
        artifact_name,
        artifact_path,
        requested_ring,
        maximum_ring,
    )?)
}

fn check(
    plan: &ChangePlan,
    proof: &ProofPackage,
    artifact_name: &str,
    artifact_path: &Path,
    requested_ring: RolloutRing,
    maximum_ring: RolloutRing,
) -> Result<ReleaseGateDecision, std::io::Error> {
    let artifact_sha256 = hash_file(artifact_path)?;
    let proof_sha256 =
        sha256_hex(&serde_json::to_vec(proof).expect("proof package is serializable"));
    let mut reasons = Vec::new();

    if proof.change_id != plan.id {
        reasons.push("proof change_id does not match plan".into());
    }
    if proof.change_class != plan.change_class {
        reasons.push("proof change class does not match plan".into());
    }
    if !proof.eligible {
        reasons.extend(
            proof
                .eligibility_reasons
                .iter()
                .map(|reason| format!("proof ineligible: {reason}")),
        );
    }
    if !proof.evidence_verified {
        reasons.push("release requires audited verifier evidence".into());
    }
    if proof.change_plan_sha256.is_none() {
        reasons.push("proof is not bound to a change-plan hash".into());
    }

    let matching_artifacts = proof
        .artifacts
        .iter()
        .filter(|artifact| artifact.name == artifact_name)
        .collect::<Vec<_>>();

    if matching_artifacts.len() != 1 {
        reasons.push(format!(
            "expected exactly one proof artifact named {artifact_name}, found {}",
            matching_artifacts.len()
        ));
    } else if matching_artifacts[0].sha256 != artifact_sha256 {
        reasons.push(format!(
            "artifact hash mismatch for {artifact_name}: proof={}, actual={artifact_sha256}",
            matching_artifacts[0].sha256
        ));
    }

    if requested_ring > maximum_ring {
        reasons.push(format!(
            "requested rollout ring {} exceeds plan maximum {}",
            ring_name(requested_ring),
            ring_name(maximum_ring)
        ));
    }

    if matches!(plan.change_class, ChangeClass::C3 | ChangeClass::C4) {
        reasons.push(
            "C3/C4 release is disabled until human approvals are cryptographically verified".into(),
        );
    }

    Ok(ReleaseGateDecision {
        change_id: plan.id.clone(),
        change_class: plan.change_class.clone(),
        requested_ring,
        maximum_ring,
        artifact_name: artifact_name.into(),
        artifact_sha256,
        proof_sha256,
        evidence_verified: proof.evidence_verified,
        eligible: reasons.is_empty(),
        reasons,
    })
}

pub fn parse_ring(value: &str) -> Result<RolloutRing, ReleaseError> {
    match value {
        "none" => Ok(RolloutRing::None),
        "simulator" => Ok(RolloutRing::Simulator),
        "developer" => Ok(RolloutRing::Developer),
        "canary" => Ok(RolloutRing::Canary),
        "fleet" => Ok(RolloutRing::Fleet),
        other => Err(ReleaseError::InvalidRing(other.into())),
    }
}

fn ring_name(ring: RolloutRing) -> &'static str {
    match ring {
        RolloutRing::None => "none",
        RolloutRing::Simulator => "simulator",
        RolloutRing::Developer => "developer",
        RolloutRing::Canary => "canary",
        RolloutRing::Fleet => "fleet",
    }
}

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
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
    fn rollout_ring_order_is_monotonic() {
        assert!(RolloutRing::None < RolloutRing::Simulator);
        assert!(RolloutRing::Simulator < RolloutRing::Developer);
        assert!(RolloutRing::Developer < RolloutRing::Canary);
        assert!(RolloutRing::Canary < RolloutRing::Fleet);
    }

    #[test]
    fn rollout_ring_parser_is_closed() {
        assert_eq!(parse_ring("canary").unwrap(), RolloutRing::Canary);
        assert!(parse_ring("production").is_err());
    }
}
