#![forbid(unsafe_code)]

use oryvael_build::{
    BuildManifest, BuildManifestError, build_from_files as build_manifest_from_files,
    compare as compare_builds,
};
use oryvael_evidence::{EvidenceError, EvidenceStatus, VerifiedEvidence, extract_from_jsonl};
use oryvael_protocol::{ChangeClass, ChangePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRef {
    pub repository: String,
    pub commit: String,
    #[serde(default)]
    pub tree: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Pass,
    Fail,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifierEvidence {
    pub name: String,
    pub principal: String,
    #[serde(default)]
    pub role: Option<String>,
    pub status: VerificationStatus,
    pub evidence_hash: String,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactEvidence {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofInput {
    pub source: SourceRef,
    #[serde(default)]
    pub verifiers: Vec<VerifierEvidence>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEvidence>,
    #[serde(default)]
    pub human_approvals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvidenceRef {
    pub audit_log: PathBuf,
    pub operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditedProofInput {
    pub source: SourceRef,
    #[serde(default)]
    pub verifier_runs: Vec<AuditEvidenceRef>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEvidence>,
    #[serde(default)]
    pub build_manifest_input: Option<PathBuf>,
    #[serde(default)]
    pub reproducible_build_input: Option<PathBuf>,
    #[serde(default)]
    pub human_approvals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildBinding {
    pub manifest_sha256: String,
    pub sbom_sha256: String,
    pub cargo_lock_sha256: String,
    pub reproducible: bool,
    #[serde(default)]
    pub independent_builder: Option<String>,
    #[serde(default)]
    pub reproducible_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPackage {
    pub change_id: String,
    pub change_class: ChangeClass,
    pub change_plan_sha256: Option<String>,
    pub evidence_verified: bool,
    pub source: SourceRef,
    pub verifiers: Vec<VerifierEvidence>,
    pub artifacts: Vec<ArtifactEvidence>,
    #[serde(default)]
    pub build: Option<BuildBinding>,
    pub eligible: bool,
    pub eligibility_reasons: Vec<String>,
    pub human_approvals: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evidence verification error: {0}")]
    Evidence(#[from] EvidenceError),
    #[error("build provenance error: {0}")]
    Build(#[from] BuildManifestError),
}

pub fn build_from_files(
    plan_path: impl AsRef<Path>,
    evidence_path: impl AsRef<Path>,
) -> Result<ProofPackage, ProofError> {
    let plan_content = fs::read_to_string(plan_path)?;
    let plan: ChangePlan = serde_json::from_str(&plan_content)?;
    let evidence: ProofInput = serde_json::from_str(&fs::read_to_string(evidence_path)?)?;
    let plan_hash = sha256_hex(plan_content.as_bytes());
    Ok(build_internal(
        &plan,
        evidence,
        Some(plan_hash),
        false,
        Vec::new(),
        None,
    ))
}

pub fn build_audited_from_files(
    plan_path: impl AsRef<Path>,
    input_path: impl AsRef<Path>,
) -> Result<ProofPackage, ProofError> {
    let plan_path = plan_path.as_ref();
    let input_path = input_path.as_ref();
    let plan_content = fs::read_to_string(plan_path)?;
    let plan: ChangePlan = serde_json::from_str(&plan_content)?;
    let plan_hash = sha256_hex(plan_content.as_bytes());
    let input: AuditedProofInput = serde_json::from_str(&fs::read_to_string(input_path)?)?;

    let mut verified = Vec::with_capacity(input.verifier_runs.len());
    for reference in &input.verifier_runs {
        verified.push(extract_from_jsonl(
            &reference.audit_log,
            &reference.operation_id,
        )?);
    }

    let mut audited_reasons = Vec::new();
    for evidence in &verified {
        if evidence.change_id != plan.id {
            audited_reasons.push(format!(
                "verifier {} belongs to change {}, expected {}",
                evidence.name, evidence.change_id, plan.id
            ));
        }
        if evidence.change_plan_sha256 != plan_hash {
            audited_reasons.push(format!(
                "verifier {} change-plan hash does not match evaluated plan",
                evidence.name
            ));
        }
    }

    let build = match input.build_manifest_input.as_ref() {
        Some(build_input) => {
            let manifest = build_manifest_from_files(plan_path, build_input)?;
            validate_build_manifest(
                &manifest,
                &input.source,
                &input.artifacts,
                "primary",
                &mut audited_reasons,
            );

            let mut binding = BuildBinding {
                manifest_sha256: manifest.manifest_sha256.clone(),
                sbom_sha256: manifest.sbom.sha256.clone(),
                cargo_lock_sha256: manifest.cargo_lock_sha256.clone(),
                reproducible: false,
                independent_builder: None,
                reproducible_manifest_sha256: None,
            };

            if let Some(reproducible_input) = input.reproducible_build_input.as_ref() {
                let independent = build_manifest_from_files(plan_path, reproducible_input)?;
                validate_build_manifest(
                    &independent,
                    &input.source,
                    &input.artifacts,
                    "independent",
                    &mut audited_reasons,
                );

                let report = compare_builds(&manifest, &independent);
                if !report.reproducible {
                    audited_reasons.extend(
                        report
                            .reasons
                            .iter()
                            .map(|reason| format!("reproducible build: {reason}")),
                    );
                }

                binding.reproducible = report.reproducible;
                binding.independent_builder = Some(independent.builder_principal.clone());
                binding.reproducible_manifest_sha256 = Some(independent.manifest_sha256.clone());
            } else if requires_reproducible_build(&plan) {
                audited_reasons.push(
                    "change plan requires build:reproducible but no independent build input was provided"
                        .into(),
                );
            }

            Some(binding)
        }
        None => {
            if matches!(
                plan.change_class,
                ChangeClass::C2 | ChangeClass::C3 | ChangeClass::C4
            ) {
                audited_reasons.push(
                    "release-grade C2/C3/C4 proof requires deterministic build provenance".into(),
                );
            }
            if input.reproducible_build_input.is_some() {
                audited_reasons.push(
                    "independent build input cannot be used without a primary build input".into(),
                );
            }
            None
        }
    };

    let declared = ProofInput {
        source: input.source,
        verifiers: verified.iter().map(map_verified_evidence).collect(),
        artifacts: input.artifacts,
        human_approvals: input.human_approvals,
    };

    Ok(build_internal(
        &plan,
        declared,
        Some(plan_hash),
        true,
        audited_reasons,
        build,
    ))
}

pub fn build(plan: &ChangePlan, input: ProofInput) -> ProofPackage {
    build_internal(plan, input, None, false, Vec::new(), None)
}

fn build_internal(
    plan: &ChangePlan,
    input: ProofInput,
    change_plan_sha256: Option<String>,
    evidence_verified: bool,
    mut reasons: Vec<String>,
    build: Option<BuildBinding>,
) -> ProofPackage {
    reasons.extend(eligibility_reasons(plan, &input));
    ProofPackage {
        change_id: plan.id.clone(),
        change_class: plan.change_class.clone(),
        change_plan_sha256,
        evidence_verified,
        source: input.source,
        verifiers: input.verifiers,
        artifacts: input.artifacts,
        build,
        eligible: reasons.is_empty(),
        eligibility_reasons: reasons,
        human_approvals: input.human_approvals,
    }
}

fn validate_build_manifest(
    manifest: &BuildManifest,
    source: &SourceRef,
    artifacts: &[ArtifactEvidence],
    label: &str,
    reasons: &mut Vec<String>,
) {
    if manifest.source.repository != source.repository
        || manifest.source.commit != source.commit
        || manifest.source.tree != source.tree
    {
        reasons.push(format!(
            "{label} build manifest source identity does not match proof source"
        ));
    }

    let declared_artifacts = artifacts
        .iter()
        .map(|artifact| (artifact.name.as_str(), artifact.sha256.as_str()))
        .collect::<BTreeSet<_>>();
    let built_artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.name.as_str(), artifact.sha256.as_str()))
        .collect::<BTreeSet<_>>();

    if declared_artifacts != built_artifacts {
        reasons.push(format!(
            "{label} build artifact set does not match proof artifacts"
        ));
    }
}

fn requires_reproducible_build(plan: &ChangePlan) -> bool {
    plan.requested_capabilities
        .iter()
        .any(|capability| capability == "build:reproducible")
}

fn map_verified_evidence(evidence: &VerifiedEvidence) -> VerifierEvidence {
    VerifierEvidence {
        name: evidence.name.clone(),
        principal: evidence.principal.clone(),
        role: Some(evidence.role.clone()),
        status: match evidence.status {
            EvidenceStatus::Pass => VerificationStatus::Pass,
            EvidenceStatus::Fail => VerificationStatus::Fail,
        },
        evidence_hash: evidence.evidence_hash.clone(),
        operation_id: evidence.operation_id.clone(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn eligibility_reasons(plan: &ChangePlan, input: &ProofInput) -> Vec<String> {
    let mut reasons = Vec::new();

    if input.source.repository.trim().is_empty() {
        reasons.push("source repository is empty".into());
    }
    if input.source.commit.trim().is_empty() {
        reasons.push("source commit is empty".into());
    }

    if !matches!(plan.change_class, ChangeClass::C0) && input.artifacts.is_empty() {
        reasons.push("non-C0 change has no release artifact".into());
    }

    for artifact in &input.artifacts {
        if artifact.name.trim().is_empty() {
            reasons.push("artifact name is empty".into());
        }
        if !is_sha256(&artifact.sha256) {
            reasons.push(format!("artifact {} has invalid SHA-256", artifact.name));
        }
    }

    for verifier in &input.verifiers {
        if verifier.name.trim().is_empty() {
            reasons.push("verifier name is empty".into());
        }
        if verifier.principal.trim().is_empty() {
            reasons.push(format!("verifier {} has empty principal", verifier.name));
        }
        if verifier.operation_id.trim().is_empty() {
            reasons.push(format!("verifier {} has empty operation_id", verifier.name));
        }
        if !is_sha256(&verifier.evidence_hash) {
            reasons.push(format!(
                "verifier {} has invalid evidence hash",
                verifier.name
            ));
        }
        if verifier.status == VerificationStatus::Fail {
            reasons.push(format!("verifier {} reported fail", verifier.name));
        }
    }

    let required = plan
        .verification
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    for name in required {
        let passes = input
            .verifiers
            .iter()
            .filter(|verifier| verifier.name == name && verifier.status == VerificationStatus::Pass)
            .collect::<Vec<_>>();

        if passes.is_empty() {
            reasons.push(format!("required verifier {name} has no passing evidence"));
            continue;
        }

        if requires_independent_verifier(&plan.change_class)
            && !passes
                .iter()
                .any(|verifier| verifier.principal != plan.producer)
        {
            reasons.push(format!(
                "required verifier {name} is not independent from producer"
            ));
        }
    }

    if matches!(plan.change_class, ChangeClass::C3 | ChangeClass::C4)
        && !input.verifiers.iter().any(|verifier| {
            verifier.status == VerificationStatus::Pass
                && verifier.principal != plan.producer
                && verifier.role.as_deref() == Some("security")
        })
    {
        reasons.push("critical change lacks independent security-role evidence".into());
    }

    if matches!(plan.change_class, ChangeClass::C4)
        && !input.verifiers.iter().any(|verifier| {
            verifier.status == VerificationStatus::Pass
                && verifier.principal != plan.producer
                && verifier.role.as_deref() == Some("reviewer")
        })
    {
        reasons.push("constitutional change lacks independent reviewer-role evidence".into());
    }

    reasons
}

fn requires_independent_verifier(class: &ChangeClass) -> bool {
    matches!(class, ChangeClass::C2 | ChangeClass::C3 | ChangeClass::C4)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(class: ChangeClass) -> ChangePlan {
        ChangePlan {
            id: "CHG-PROOF-1".into(),
            intent: "proof test".into(),
            change_class: class,
            producer: "developer-ai/1".into(),
            components: vec!["demo".into()],
            paths: vec!["src/lib.rs".into()],
            requested_capabilities: vec![],
            dependencies_added: vec![],
            verification: vec!["test".into(), "security".into()],
            max_rollout_ring: Some("canary".into()),
            rollback: "rollback".into(),
        }
    }

    fn evidence(verifier_principal: &str) -> ProofInput {
        ProofInput {
            source: SourceRef {
                repository: "jellero/ORYVAEL".into(),
                commit: "abc123".into(),
                tree: None,
            },
            verifiers: vec![
                VerifierEvidence {
                    name: "test".into(),
                    principal: verifier_principal.into(),
                    role: Some("test".into()),
                    status: VerificationStatus::Pass,
                    evidence_hash: "a".repeat(64),
                    operation_id: "op-test".into(),
                },
                VerifierEvidence {
                    name: "security".into(),
                    principal: "security-ai/1".into(),
                    role: Some("security".into()),
                    status: VerificationStatus::Pass,
                    evidence_hash: "b".repeat(64),
                    operation_id: "op-security".into(),
                },
            ],
            artifacts: vec![ArtifactEvidence {
                name: "system.img".into(),
                sha256: "c".repeat(64),
            }],
            human_approvals: vec![],
        }
    }

    #[test]
    fn c2_requires_independent_verification() {
        let package = build(&plan(ChangeClass::C2), evidence("developer-ai/1"));
        assert!(!package.eligible);
        assert!(
            package
                .eligibility_reasons
                .iter()
                .any(|reason| reason.contains("test is not independent"))
        );
    }

    #[test]
    fn c2_independent_evidence_is_eligible() {
        let package = build(&plan(ChangeClass::C2), evidence("test-ai/1"));
        assert!(package.eligible);
    }

    #[test]
    fn failed_verifier_vetoes_release() {
        let mut evidence = evidence("test-ai/1");
        evidence.verifiers[1].status = VerificationStatus::Fail;
        let package = build(&plan(ChangeClass::C2), evidence);
        assert!(!package.eligible);
    }

    #[test]
    fn c3_proof_defers_human_authority_to_release_gate() {
        let package = build(&plan(ChangeClass::C3), evidence("test-ai/1"));
        assert!(package.eligible);
        assert!(package.human_approvals.is_empty());
    }
}
