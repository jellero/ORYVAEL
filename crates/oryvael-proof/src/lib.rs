#![forbid(unsafe_code)]

use oryvael_protocol::{ChangeClass, ChangePlan};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
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
pub struct ProofPackage {
    pub change_id: String,
    pub change_class: ChangeClass,
    pub source: SourceRef,
    pub verifiers: Vec<VerifierEvidence>,
    pub artifacts: Vec<ArtifactEvidence>,
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
}

pub fn build_from_files(
    plan_path: impl AsRef<Path>,
    evidence_path: impl AsRef<Path>,
) -> Result<ProofPackage, ProofError> {
    let plan: ChangePlan = serde_json::from_str(&fs::read_to_string(plan_path)?)?;
    let evidence: ProofInput = serde_json::from_str(&fs::read_to_string(evidence_path)?)?;
    Ok(build(&plan, evidence))
}

pub fn build(plan: &ChangePlan, input: ProofInput) -> ProofPackage {
    let reasons = eligibility_reasons(plan, &input);
    ProofPackage {
        change_id: plan.id.clone(),
        change_class: plan.change_class.clone(),
        source: input.source,
        verifiers: input.verifiers,
        artifacts: input.artifacts,
        eligible: reasons.is_empty(),
        eligibility_reasons: reasons,
        human_approvals: input.human_approvals,
    }
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

    if requires_human_approval(&plan.change_class)
        && input
            .human_approvals
            .iter()
            .all(|approval| approval.trim().is_empty())
    {
        reasons.push("critical/constitutional change lacks human approval reference".into());
    }

    reasons
}

fn requires_independent_verifier(class: &ChangeClass) -> bool {
    matches!(class, ChangeClass::C2 | ChangeClass::C3 | ChangeClass::C4)
}

fn requires_human_approval(class: &ChangeClass) -> bool {
    matches!(class, ChangeClass::C3 | ChangeClass::C4)
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
                    status: VerificationStatus::Pass,
                    evidence_hash: "a".repeat(64),
                    operation_id: "op-test".into(),
                },
                VerifierEvidence {
                    name: "security".into(),
                    principal: "security-ai/1".into(),
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
    fn c3_requires_human_approval_reference() {
        let package = build(&plan(ChangeClass::C3), evidence("test-ai/1"));
        assert!(!package.eligible);

        let mut approved = evidence("test-ai/1");
        approved
            .human_approvals
            .push("human-approval:example".into());
        assert!(build(&plan(ChangeClass::C3), approved).eligible);
    }
}
