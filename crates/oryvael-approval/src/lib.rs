#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use oryvael_protocol::ChangeClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use thiserror::Error;

const APPROVAL_DOMAIN: &str = "ORYVAEL-RELEASE-APPROVAL-V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalContext {
    pub change_id: String,
    pub change_class: ChangeClass,
    pub change_plan_sha256: String,
    pub proof_sha256: String,
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub rollout_ring: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalStatement {
    pub version: u32,
    pub signer_id: String,
    pub context: ApprovalContext,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ApprovalBundle {
    #[serde(default)]
    pub approvals: Vec<ApprovalStatement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedSigner {
    pub id: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub allowed_classes: Vec<ChangeClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalThresholds {
    pub c3: u32,
    pub c4: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalTrustPolicy {
    pub version: u32,
    pub thresholds: ApprovalThresholds,
    #[serde(default)]
    pub signers: Vec<TrustedSigner>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalVerification {
    pub required: u32,
    pub valid_signers: Vec<String>,
    pub eligible: bool,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid hexadecimal value: {0}")]
    InvalidHex(String),
    #[error("invalid private key length: expected 32 bytes")]
    InvalidPrivateKeyLength,
    #[error("invalid public key for signer {0}")]
    InvalidPublicKey(String),
    #[error("invalid signature length for signer {0}")]
    InvalidSignatureLength(String),
    #[error("unsupported approval version: {0}")]
    UnsupportedVersion(u32),
}

pub fn public_key_from_private_file(
    private_key_path: impl AsRef<Path>,
) -> Result<String, ApprovalError> {
    let signing_key = load_signing_key(private_key_path)?;
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

pub fn sign_from_files(
    private_key_path: impl AsRef<Path>,
    signer_id: &str,
    context_path: impl AsRef<Path>,
) -> Result<ApprovalStatement, ApprovalError> {
    let context: ApprovalContext =
        serde_json::from_str(&fs::read_to_string(context_path.as_ref())?)?;
    let signing_key = load_signing_key(private_key_path)?;
    Ok(sign(&signing_key, signer_id, context))
}

pub fn verify_from_files(
    policy_path: impl AsRef<Path>,
    bundle_path: impl AsRef<Path>,
    context_path: impl AsRef<Path>,
) -> Result<ApprovalVerification, ApprovalError> {
    let policy: ApprovalTrustPolicy =
        serde_json::from_str(&fs::read_to_string(policy_path.as_ref())?)?;
    let bundle: ApprovalBundle = serde_json::from_str(&fs::read_to_string(bundle_path.as_ref())?)?;
    let context: ApprovalContext =
        serde_json::from_str(&fs::read_to_string(context_path.as_ref())?)?;
    verify(&policy, &bundle, &context)
}

pub fn sign(
    signing_key: &SigningKey,
    signer_id: &str,
    context: ApprovalContext,
) -> ApprovalStatement {
    let payload = canonical_payload(signer_id, &context);
    let signature = signing_key.sign(&payload);

    ApprovalStatement {
        version: 1,
        signer_id: signer_id.to_owned(),
        context,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

pub fn verify(
    policy: &ApprovalTrustPolicy,
    bundle: &ApprovalBundle,
    context: &ApprovalContext,
) -> Result<ApprovalVerification, ApprovalError> {
    if policy.version != 1 {
        return Err(ApprovalError::UnsupportedVersion(policy.version));
    }

    let required = threshold_for(&policy.thresholds, &context.change_class);
    if matches!(context.change_class, ChangeClass::C3 | ChangeClass::C4) && required == 0 {
        return Ok(ApprovalVerification {
            required,
            valid_signers: Vec::new(),
            eligible: false,
            reasons: vec!["human approval threshold must be greater than zero".into()],
            warnings: Vec::new(),
        });
    }
    if required == 0 {
        return Ok(ApprovalVerification {
            required,
            valid_signers: Vec::new(),
            eligible: true,
            reasons: Vec::new(),
            warnings: Vec::new(),
        });
    }

    let mut valid = BTreeSet::new();
    let mut warnings = Vec::new();

    for approval in &bundle.approvals {
        if approval.version != 1 {
            warnings.push(format!(
                "approval from {} uses unsupported version {}",
                approval.signer_id, approval.version
            ));
            continue;
        }

        if approval.context != *context {
            warnings.push(format!(
                "approval from {} is bound to a different release context",
                approval.signer_id
            ));
            continue;
        }

        let Some(signer) = policy
            .signers
            .iter()
            .find(|signer| signer.id == approval.signer_id)
        else {
            warnings.push(format!(
                "approval signer {} is not in the root trust policy",
                approval.signer_id
            ));
            continue;
        };

        if !signer.allowed_classes.contains(&context.change_class) {
            warnings.push(format!(
                "approval signer {} is not authorized for {:?}",
                approval.signer_id, context.change_class
            ));
            continue;
        }

        if valid.contains(&approval.signer_id) {
            warnings.push(format!(
                "duplicate approval from signer {} ignored",
                approval.signer_id
            ));
            continue;
        }

        let public_bytes = decode_fixed::<32>(&signer.public_key_hex)
            .map_err(|_| ApprovalError::InvalidPublicKey(signer.id.clone()))?;
        let verifying_key = VerifyingKey::from_bytes(&public_bytes)
            .map_err(|_| ApprovalError::InvalidPublicKey(signer.id.clone()))?;

        let signature_bytes = decode_fixed::<64>(&approval.signature_hex)
            .map_err(|_| ApprovalError::InvalidSignatureLength(signer.id.clone()))?;
        let signature = Signature::from_bytes(&signature_bytes);
        let payload = canonical_payload(&approval.signer_id, context);

        if verifying_key.verify(&payload, &signature).is_ok() {
            valid.insert(approval.signer_id.clone());
        } else {
            warnings.push(format!(
                "signature verification failed for signer {}",
                approval.signer_id
            ));
        }
    }

    let valid_signers = valid.into_iter().collect::<Vec<_>>();
    let mut reasons = Vec::new();
    if valid_signers.len() < required as usize {
        reasons.push(format!(
            "human approval threshold not met: required {}, valid {}",
            required,
            valid_signers.len()
        ));
    }

    Ok(ApprovalVerification {
        required,
        valid_signers,
        eligible: reasons.is_empty(),
        reasons,
        warnings,
    })
}

pub fn threshold_for(thresholds: &ApprovalThresholds, class: &ChangeClass) -> u32 {
    match class {
        ChangeClass::C0 | ChangeClass::C1 | ChangeClass::C2 => 0,
        ChangeClass::C3 => thresholds.c3,
        ChangeClass::C4 => thresholds.c4,
    }
}

fn load_signing_key(path: impl AsRef<Path>) -> Result<SigningKey, ApprovalError> {
    let encoded = fs::read_to_string(path)?;
    let decoded = hex::decode(encoded.trim())
        .map_err(|error| ApprovalError::InvalidHex(error.to_string()))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ApprovalError::InvalidPrivateKeyLength)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], ApprovalError> {
    let decoded =
        hex::decode(encoded.trim()).map_err(|error| ApprovalError::InvalidHex(error.to_string()))?;
    decoded
        .try_into()
        .map_err(|_| ApprovalError::InvalidHex(format!("expected {N} bytes")))
}

fn canonical_payload(signer_id: &str, context: &ApprovalContext) -> Vec<u8> {
    let class = match context.change_class {
        ChangeClass::C0 => "C0",
        ChangeClass::C1 => "C1",
        ChangeClass::C2 => "C2",
        ChangeClass::C3 => "C3",
        ChangeClass::C4 => "C4",
    };

    let fields = [
        APPROVAL_DOMAIN,
        signer_id,
        context.change_id.as_str(),
        class,
        context.change_plan_sha256.as_str(),
        context.proof_sha256.as_str(),
        context.artifact_name.as_str(),
        context.artifact_sha256.as_str(),
        context.rollout_ring.as_str(),
    ];

    let mut payload = Vec::new();
    for field in fields {
        let bytes = field.as_bytes();
        payload.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        payload.extend_from_slice(bytes);
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(class: ChangeClass) -> ApprovalContext {
        ApprovalContext {
            change_id: "CHG-APPROVAL-1".into(),
            change_class: class,
            change_plan_sha256: "a".repeat(64),
            proof_sha256: "b".repeat(64),
            artifact_name: "system.img".into(),
            artifact_sha256: "c".repeat(64),
            rollout_ring: "canary".into(),
        }
    }

    fn signer(seed: u8, id: &str, classes: Vec<ChangeClass>) -> (SigningKey, TrustedSigner) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let trusted = TrustedSigner {
            id: id.into(),
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            allowed_classes: classes,
        };
        (key, trusted)
    }

    #[test]
    fn c2_needs_no_human_signature() {
        let policy = ApprovalTrustPolicy {
            version: 1,
            thresholds: ApprovalThresholds { c3: 1, c4: 2 },
            signers: vec![],
        };

        let result = verify(
            &policy,
            &ApprovalBundle::default(),
            &context(ChangeClass::C2),
        )
        .unwrap();
        assert!(result.eligible);
        assert_eq!(result.required, 0);
    }

    #[test]
    fn c3_accepts_one_authorized_signature() {
        let (key, trusted) = signer(7, "human/alice", vec![ChangeClass::C3]);
        let ctx = context(ChangeClass::C3);
        let approval = sign(&key, "human/alice", ctx.clone());
        let policy = ApprovalTrustPolicy {
            version: 1,
            thresholds: ApprovalThresholds { c3: 1, c4: 2 },
            signers: vec![trusted],
        };

        let result = verify(
            &policy,
            &ApprovalBundle {
                approvals: vec![approval],
            },
            &ctx,
        )
        .unwrap();

        assert!(result.eligible);
        assert_eq!(result.valid_signers, vec!["human/alice"]);
    }

    #[test]
    fn modified_artifact_invalidates_signature_context() {
        let (key, trusted) = signer(9, "human/alice", vec![ChangeClass::C3]);
        let ctx = context(ChangeClass::C3);
        let approval = sign(&key, "human/alice", ctx.clone());

        let mut modified = ctx;
        modified.artifact_sha256 = "d".repeat(64);

        let policy = ApprovalTrustPolicy {
            version: 1,
            thresholds: ApprovalThresholds { c3: 1, c4: 2 },
            signers: vec![trusted],
        };

        let result = verify(
            &policy,
            &ApprovalBundle {
                approvals: vec![approval],
            },
            &modified,
        )
        .unwrap();

        assert!(!result.eligible);
        assert!(result.valid_signers.is_empty());
    }

    #[test]
    fn duplicate_signer_does_not_satisfy_c4_threshold() {
        let (key, trusted) = signer(11, "human/alice", vec![ChangeClass::C4]);
        let ctx = context(ChangeClass::C4);
        let approval = sign(&key, "human/alice", ctx.clone());

        let policy = ApprovalTrustPolicy {
            version: 1,
            thresholds: ApprovalThresholds { c3: 1, c4: 2 },
            signers: vec![trusted],
        };

        let result = verify(
            &policy,
            &ApprovalBundle {
                approvals: vec![approval.clone(), approval],
            },
            &ctx,
        )
        .unwrap();

        assert!(!result.eligible);
        assert_eq!(result.valid_signers.len(), 1);
    }
}
