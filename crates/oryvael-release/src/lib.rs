#![forbid(unsafe_code)]

use oryvael_approval::{
    ApprovalBundle, ApprovalContext, ApprovalError, ApprovalTrustPolicy, ApprovalVerification,
    verify as verify_approvals,
};
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
    pub approval_required: bool,
    pub approval_threshold: u32,
    pub valid_approval_signers: Vec<String>,
    pub approval_warnings: Vec<String>,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("approval error: {0}")]
    Approval(#[from] ApprovalError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid rollout ring: {0}")]
    InvalidRing(String),
    #[error("artifact is not a file: {0}")]
    InvalidArtifact(String),
    #[error("release context is not technically eligible: {0}")]
    BaseIneligible(String),
}

struct PreparedRelease {
    plan: ChangePlan,
    proof: ProofPackage,
    requested_ring: RolloutRing,
    maximum_ring: RolloutRing,
    artifact_name: String,
    artifact_sha256: String,
    proof_sha256: String,
    reasons: Vec<String>,
}

pub fn check_from_files(
    plan_path: impl AsRef<Path>,
    audited_input_path: impl AsRef<Path>,
    artifact_name: &str,
    artifact_path: impl AsRef<Path>,
    requested_ring: &str,
) -> Result<ReleaseGateDecision, ReleaseError> {
    let prepared = prepare_release(
        plan_path.as_ref(),
        audited_input_path.as_ref(),
        artifact_name,
        artifact_path.as_ref(),
        requested_ring,
    )?;
    Ok(finalize(prepared, None))
}

pub fn check_from_files_with_approvals(
    plan_path: impl AsRef<Path>,
    audited_input_path: impl AsRef<Path>,
    artifact_name: &str,
    artifact_path: impl AsRef<Path>,
    requested_ring: &str,
    approval_policy_path: impl AsRef<Path>,
    approval_bundle_path: impl AsRef<Path>,
) -> Result<ReleaseGateDecision, ReleaseError> {
    let prepared = prepare_release(
        plan_path.as_ref(),
        audited_input_path.as_ref(),
        artifact_name,
        artifact_path.as_ref(),
        requested_ring,
    )?;

    let context = approval_context(&prepared)?;
    let policy: ApprovalTrustPolicy =
        serde_json::from_str(&fs::read_to_string(approval_policy_path.as_ref())?)?;
    let bundle: ApprovalBundle =
        serde_json::from_str(&fs::read_to_string(approval_bundle_path.as_ref())?)?;
    let verification = verify_approvals(&policy, &bundle, &context)?;

    Ok(finalize(prepared, Some(verification)))
}

pub fn approval_context_from_files(
    plan_path: impl AsRef<Path>,
    audited_input_path: impl AsRef<Path>,
    artifact_name: &str,
    artifact_path: impl AsRef<Path>,
    requested_ring: &str,
) -> Result<ApprovalContext, ReleaseError> {
    let prepared = prepare_release(
        plan_path.as_ref(),
        audited_input_path.as_ref(),
        artifact_name,
        artifact_path.as_ref(),
        requested_ring,
    )?;

    if !prepared.reasons.is_empty() {
        return Err(ReleaseError::BaseIneligible(prepared.reasons.join("; ")));
    }

    approval_context(&prepared)
}

fn prepare_release(
    plan_path: &Path,
    audited_input_path: &Path,
    artifact_name: &str,
    artifact_path: &Path,
    requested_ring: &str,
) -> Result<PreparedRelease, ReleaseError> {
    let plan_content = fs::read_to_string(plan_path)?;
    let plan: ChangePlan = serde_json::from_str(&plan_content)?;
    let proof = build_audited_from_files(plan_path, audited_input_path)?;

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
    let artifact_sha256 = hash_file(artifact_path)?;
    let proof_sha256 =
        sha256_hex(&serde_json::to_vec(&proof).expect("proof package is serializable"));
    let reasons = base_reasons(
        &plan,
        &proof,
        artifact_name,
        &artifact_sha256,
        requested_ring,
        maximum_ring,
    );

    Ok(PreparedRelease {
        plan,
        proof,
        requested_ring,
        maximum_ring,
        artifact_name: artifact_name.into(),
        artifact_sha256,
        proof_sha256,
        reasons,
    })
}

fn base_reasons(
    plan: &ChangePlan,
    proof: &ProofPackage,
    artifact_name: &str,
    artifact_sha256: &str,
    requested_ring: RolloutRing,
    maximum_ring: RolloutRing,
) -> Vec<String> {
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

    reasons
}

fn approval_context(prepared: &PreparedRelease) -> Result<ApprovalContext, ReleaseError> {
    let change_plan_sha256 = prepared
        .proof
        .change_plan_sha256
        .clone()
        .ok_or_else(|| ReleaseError::BaseIneligible("missing change-plan hash".into()))?;

    Ok(ApprovalContext {
        change_id: prepared.plan.id.clone(),
        change_class: prepared.plan.change_class.clone(),
        change_plan_sha256,
        proof_sha256: prepared.proof_sha256.clone(),
        artifact_name: prepared.artifact_name.clone(),
        artifact_sha256: prepared.artifact_sha256.clone(),
        rollout_ring: ring_name(prepared.requested_ring).into(),
    })
}

fn finalize(
    mut prepared: PreparedRelease,
    approval: Option<ApprovalVerification>,
) -> ReleaseGateDecision {
    let approval_required = matches!(
        prepared.plan.change_class,
        ChangeClass::C3 | ChangeClass::C4
    );

    let (approval_threshold, valid_approval_signers, approval_warnings) = if approval_required {
        match approval {
            Some(verification) => {
                if !verification.eligible {
                    prepared.reasons.extend(verification.reasons);
                }
                (
                    verification.required,
                    verification.valid_signers,
                    verification.warnings,
                )
            }
            None => {
                prepared.reasons.push(
                    "critical release requires cryptographically verified human approval".into(),
                );
                (0, Vec::new(), Vec::new())
            }
        }
    } else {
        (0, Vec::new(), Vec::new())
    };

    ReleaseGateDecision {
        change_id: prepared.plan.id,
        change_class: prepared.plan.change_class,
        requested_ring: prepared.requested_ring,
        maximum_ring: prepared.maximum_ring,
        artifact_name: prepared.artifact_name,
        artifact_sha256: prepared.artifact_sha256,
        proof_sha256: prepared.proof_sha256,
        evidence_verified: prepared.proof.evidence_verified,
        approval_required,
        approval_threshold,
        valid_approval_signers,
        approval_warnings,
        eligible: prepared.reasons.is_empty(),
        reasons: prepared.reasons,
    }
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
