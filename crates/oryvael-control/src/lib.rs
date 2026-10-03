#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const CONTROL_SIGNATURE_DOMAIN: &[u8] = b"ORYVAEL-CONTROL-V1";
pub const ROOT_POLICY_ENV: &str = "ORYVAEL_ROOT_POLICY";
pub const ROOT_POLICY_MIN_EPOCH_ENV: &str = "ORYVAEL_ROOT_POLICY_MIN_EPOCH";
pub const DEFAULT_ROOT_POLICY: &str = "/etc/oryvael/root-policy.json";
pub const DEFAULT_ROOT_POLICY_MIN_EPOCH: &str = "/etc/oryvael/root-policy.min-epoch";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    ToolCatalog,
    ChangePlan,
    PrincipalPolicy,
    WorkspaceRegistry,
}

impl ControlKind {
    pub fn parse(value: &str) -> Result<Self, ControlError> {
        match value {
            "tool_catalog" => Ok(Self::ToolCatalog),
            "change_plan" => Ok(Self::ChangePlan),
            "principal_policy" => Ok(Self::PrincipalPolicy),
            "workspace_registry" => Ok(Self::WorkspaceRegistry),
            other => Err(ControlError::UnknownKind(other.into())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolCatalog => "tool_catalog",
            Self::ChangePlan => "change_plan",
            Self::PrincipalPolicy => "principal_policy",
            Self::WorkspaceRegistry => "workspace_registry",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootTrustPolicy {
    pub version: u32,
    pub epoch: u64,
    #[serde(default)]
    pub signers: Vec<RootSigner>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootSigner {
    pub id: String,
    pub key_version: u64,
    pub public_key_hex: String,
    pub status: SignerStatus,
    pub allowed_kinds: Vec<ControlKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlSignature {
    pub version: u32,
    pub kind: ControlKind,
    pub signer_id: String,
    pub key_version: u64,
    pub artifact_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedControl {
    pub kind: ControlKind,
    pub signer_id: String,
    pub key_version: u64,
    pub artifact_sha256: String,
    pub root_policy_sha256: String,
    pub signature_sha256: String,
    pub root_policy_epoch: u64,
    pub root_policy_path: PathBuf,
    pub signature_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("ORYVAEL root trust policy is unavailable: {0}")]
    MissingRootPolicy(String),
    #[error("invalid minimum root epoch in {0}: {1}")]
    InvalidMinimumEpoch(String, String),
    #[error("root trust policy version {0} is unsupported")]
    UnsupportedRootVersion(u32),
    #[error("root trust policy epoch {actual} is below required minimum {minimum}")]
    RootEpochRollback { actual: u64, minimum: u64 },
    #[error("control signature version {0} is unsupported")]
    UnsupportedSignatureVersion(u32),
    #[error("unknown control artifact kind: {0}")]
    UnknownKind(String),
    #[error("control signature kind mismatch: expected {expected}, got {actual}")]
    KindMismatch { expected: String, actual: String },
    #[error("duplicate root signer identity/version: {id}@{key_version}")]
    DuplicateSigner { id: String, key_version: u64 },
    #[error("root signer is not trusted: {id}@{key_version}")]
    UntrustedSigner { id: String, key_version: u64 },
    #[error("root signer is revoked: {id}@{key_version}")]
    RevokedSigner { id: String, key_version: u64 },
    #[error("root signer {id}@{key_version} is not authorized for {kind}")]
    KindNotAuthorized {
        id: String,
        key_version: u64,
        kind: String,
    },
    #[error("invalid public key for root signer {id}@{key_version}")]
    InvalidPublicKey { id: String, key_version: u64 },
    #[error("invalid signature length for root signer {id}@{key_version}")]
    InvalidSignatureLength { id: String, key_version: u64 },
    #[error(
        "control artifact hash mismatch: signature binds {signed}, actual artifact is {actual}"
    )]
    ArtifactHashMismatch { signed: String, actual: String },
    #[error("control signature verification failed for root signer {id}@{key_version}")]
    SignatureInvalid { id: String, key_version: u64 },
    #[error("private signing key must contain exactly 32 bytes encoded as 64 hex characters")]
    InvalidPrivateKey,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn verify_from_env(
    artifact_path: impl AsRef<Path>,
    kind: ControlKind,
) -> Result<VerifiedControl, ControlError> {
    let root = env::var(ROOT_POLICY_ENV).unwrap_or_else(|_| DEFAULT_ROOT_POLICY.into());
    if !Path::new(&root).is_file() {
        return Err(ControlError::MissingRootPolicy(root));
    }
    verify_from_files(artifact_path, root, kind)
}

pub fn verify_from_files(
    artifact_path: impl AsRef<Path>,
    root_policy_path: impl AsRef<Path>,
    kind: ControlKind,
) -> Result<VerifiedControl, ControlError> {
    let artifact_path = canonical_file(artifact_path.as_ref())?;
    let root_policy_path = canonical_file(root_policy_path.as_ref())?;
    let signature_path = canonical_file(&signature_sidecar_path(&artifact_path))?;

    let artifact_bytes = fs::read(&artifact_path)?;
    let root_policy_bytes = fs::read(&root_policy_path)?;
    let signature_bytes = fs::read(&signature_path)?;

    let policy: RootTrustPolicy = serde_json::from_slice(&root_policy_bytes)?;
    let statement: ControlSignature = serde_json::from_slice(&signature_bytes)?;
    validate_root_policy(&policy)?;

    if let Some(minimum) = minimum_root_epoch()? {
        if policy.epoch < minimum {
            return Err(ControlError::RootEpochRollback {
                actual: policy.epoch,
                minimum,
            });
        }
    }

    if statement.version != 1 {
        return Err(ControlError::UnsupportedSignatureVersion(statement.version));
    }
    if statement.kind != kind {
        return Err(ControlError::KindMismatch {
            expected: kind.as_str().into(),
            actual: statement.kind.as_str().into(),
        });
    }

    let artifact_sha256 = sha256_hex(&artifact_bytes);
    if statement.artifact_sha256 != artifact_sha256 {
        return Err(ControlError::ArtifactHashMismatch {
            signed: statement.artifact_sha256,
            actual: artifact_sha256,
        });
    }

    let signer = policy
        .signers
        .iter()
        .find(|signer| {
            signer.id == statement.signer_id && signer.key_version == statement.key_version
        })
        .ok_or_else(|| ControlError::UntrustedSigner {
            id: statement.signer_id.clone(),
            key_version: statement.key_version,
        })?;

    if signer.status == SignerStatus::Revoked {
        return Err(ControlError::RevokedSigner {
            id: signer.id.clone(),
            key_version: signer.key_version,
        });
    }
    if !signer.allowed_kinds.contains(&kind) {
        return Err(ControlError::KindNotAuthorized {
            id: signer.id.clone(),
            key_version: signer.key_version,
            kind: kind.as_str().into(),
        });
    }

    let public_bytes =
        decode_fixed::<32>(&signer.public_key_hex).map_err(|_| ControlError::InvalidPublicKey {
            id: signer.id.clone(),
            key_version: signer.key_version,
        })?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_bytes).map_err(|_| ControlError::InvalidPublicKey {
            id: signer.id.clone(),
            key_version: signer.key_version,
        })?;
    let signature_bytes_raw = decode_fixed::<64>(&statement.signature_hex).map_err(|_| {
        ControlError::InvalidSignatureLength {
            id: signer.id.clone(),
            key_version: signer.key_version,
        }
    })?;
    let signature = Signature::from_bytes(&signature_bytes_raw);
    let payload = signature_payload(
        statement.kind,
        &statement.signer_id,
        statement.key_version,
        &statement.artifact_sha256,
    );

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| ControlError::SignatureInvalid {
            id: signer.id.clone(),
            key_version: signer.key_version,
        })?;

    Ok(VerifiedControl {
        kind,
        signer_id: signer.id.clone(),
        key_version: signer.key_version,
        artifact_sha256: statement.artifact_sha256,
        root_policy_sha256: sha256_hex(&root_policy_bytes),
        signature_sha256: sha256_hex(&signature_bytes),
        root_policy_epoch: policy.epoch,
        root_policy_path,
        signature_path,
    })
}

pub fn sign_from_files(
    private_key_path: impl AsRef<Path>,
    signer_id: &str,
    key_version: u64,
    kind: ControlKind,
    artifact_path: impl AsRef<Path>,
) -> Result<ControlSignature, ControlError> {
    let private_key = read_private_key(private_key_path.as_ref())?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let artifact_sha256 = sha256_hex(&fs::read(artifact_path)?);
    let payload = signature_payload(kind, signer_id, key_version, &artifact_sha256);
    let signature = signing_key.sign(&payload);

    Ok(ControlSignature {
        version: 1,
        kind,
        signer_id: signer_id.into(),
        key_version,
        artifact_sha256,
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

pub fn public_key_from_private_file(
    private_key_path: impl AsRef<Path>,
) -> Result<String, ControlError> {
    let private_key = read_private_key(private_key_path.as_ref())?;
    Ok(hex::encode(
        SigningKey::from_bytes(&private_key)
            .verifying_key()
            .to_bytes(),
    ))
}

pub fn signature_sidecar_path(artifact_path: &Path) -> PathBuf {
    let name = artifact_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("control");
    artifact_path.with_file_name(format!("{name}.control.json"))
}

fn minimum_root_epoch() -> Result<Option<u64>, ControlError> {
    if let Ok(raw) = env::var(ROOT_POLICY_MIN_EPOCH_ENV) {
        let minimum = raw.trim().parse::<u64>().map_err(|_| {
            ControlError::InvalidMinimumEpoch(ROOT_POLICY_MIN_EPOCH_ENV.into(), raw.clone())
        })?;
        return Ok(Some(minimum));
    }

    let path = Path::new(DEFAULT_ROOT_POLICY_MIN_EPOCH);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let minimum = raw.trim().parse::<u64>().map_err(|_| {
        ControlError::InvalidMinimumEpoch(DEFAULT_ROOT_POLICY_MIN_EPOCH.into(), raw.clone())
    })?;
    Ok(Some(minimum))
}

fn validate_root_policy(policy: &RootTrustPolicy) -> Result<(), ControlError> {
    if policy.version != 1 {
        return Err(ControlError::UnsupportedRootVersion(policy.version));
    }
    let mut identities = BTreeSet::new();
    for signer in &policy.signers {
        if !identities.insert((signer.id.as_str(), signer.key_version)) {
            return Err(ControlError::DuplicateSigner {
                id: signer.id.clone(),
                key_version: signer.key_version,
            });
        }
    }
    Ok(())
}

fn signature_payload(
    kind: ControlKind,
    signer_id: &str,
    key_version: u64,
    artifact_sha256: &str,
) -> Vec<u8> {
    let key_version = key_version.to_string();
    let mut payload = Vec::new();
    for part in [
        CONTROL_SIGNATURE_DOMAIN,
        kind.as_str().as_bytes(),
        signer_id.as_bytes(),
        key_version.as_bytes(),
        artifact_sha256.as_bytes(),
    ] {
        if !payload.is_empty() {
            payload.push(0);
        }
        payload.extend_from_slice(part);
    }
    payload
}

fn read_private_key(path: &Path) -> Result<[u8; 32], ControlError> {
    let raw = fs::read_to_string(path)?;
    decode_fixed::<32>(raw.trim()).map_err(|_| ControlError::InvalidPrivateKey)
}

fn canonical_file(path: &Path) -> Result<PathBuf, ControlError> {
    let path = fs::canonicalize(path)?;
    if !path.is_file() {
        return Err(ControlError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("not a file: {}", path.display()),
        )));
    }
    Ok(path)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let decoded = hex::decode(value)?;
    decoded
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = env::temp_dir().join(format!("oryvael-control-{label}-{nonce}"));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn active_rotated_key_verifies_and_revoked_key_is_rejected() {
        let dir = temp_dir("rotation");
        let artifact = dir.join("plan.json");
        fs::write(&artifact, b"{\"id\":\"CHG-1\"}\n").expect("artifact");

        let old_key = [7_u8; 32];
        let new_key = [9_u8; 32];
        let old_signing = SigningKey::from_bytes(&old_key);
        let new_signing = SigningKey::from_bytes(&new_key);
        let root = RootTrustPolicy {
            version: 1,
            epoch: 2,
            signers: vec![
                RootSigner {
                    id: "governance-root".into(),
                    key_version: 1,
                    public_key_hex: hex::encode(old_signing.verifying_key().to_bytes()),
                    status: SignerStatus::Revoked,
                    allowed_kinds: vec![ControlKind::ChangePlan],
                },
                RootSigner {
                    id: "governance-root".into(),
                    key_version: 2,
                    public_key_hex: hex::encode(new_signing.verifying_key().to_bytes()),
                    status: SignerStatus::Active,
                    allowed_kinds: vec![ControlKind::ChangePlan],
                },
            ],
        };
        let root_path = dir.join("root.json");
        fs::write(&root_path, serde_json::to_vec(&root).expect("root json")).expect("root");

        let hash = sha256_hex(&fs::read(&artifact).expect("artifact bytes"));
        let payload = signature_payload(ControlKind::ChangePlan, "governance-root", 2, &hash);
        let statement = ControlSignature {
            version: 1,
            kind: ControlKind::ChangePlan,
            signer_id: "governance-root".into(),
            key_version: 2,
            artifact_sha256: hash.clone(),
            signature_hex: hex::encode(new_signing.sign(&payload).to_bytes()),
        };
        let sidecar = signature_sidecar_path(&artifact);
        fs::write(
            &sidecar,
            serde_json::to_vec(&statement).expect("statement json"),
        )
        .expect("statement");
        assert!(verify_from_files(&artifact, &root_path, ControlKind::ChangePlan).is_ok());

        let old_payload = signature_payload(ControlKind::ChangePlan, "governance-root", 1, &hash);
        let old_statement = ControlSignature {
            version: 1,
            kind: ControlKind::ChangePlan,
            signer_id: "governance-root".into(),
            key_version: 1,
            artifact_sha256: hash,
            signature_hex: hex::encode(old_signing.sign(&old_payload).to_bytes()),
        };
        fs::write(
            &sidecar,
            serde_json::to_vec(&old_statement).expect("old statement json"),
        )
        .expect("old statement");
        assert!(matches!(
            verify_from_files(&artifact, &root_path, ControlKind::ChangePlan),
            Err(ControlError::RevokedSigner { .. })
        ));
    }

    #[test]
    fn mutated_artifact_is_rejected() {
        let dir = temp_dir("tamper");
        let artifact = dir.join("principal.json");
        fs::write(&artifact, b"original").expect("artifact");
        let key = [3_u8; 32];
        let key_path = dir.join("key.hex");
        fs::write(&key_path, hex::encode(key)).expect("key");
        let signing = SigningKey::from_bytes(&key);
        let root = RootTrustPolicy {
            version: 1,
            epoch: 1,
            signers: vec![RootSigner {
                id: "root".into(),
                key_version: 1,
                public_key_hex: hex::encode(signing.verifying_key().to_bytes()),
                status: SignerStatus::Active,
                allowed_kinds: vec![ControlKind::PrincipalPolicy],
            }],
        };
        let root_path = dir.join("root.json");
        fs::write(&root_path, serde_json::to_vec(&root).expect("root json")).expect("root");
        let statement = sign_from_files(
            &key_path,
            "root",
            1,
            ControlKind::PrincipalPolicy,
            &artifact,
        )
        .expect("sign");
        fs::write(
            signature_sidecar_path(&artifact),
            serde_json::to_vec(&statement).expect("statement json"),
        )
        .expect("statement");
        fs::write(&artifact, b"mutated").expect("mutate");
        assert!(matches!(
            verify_from_files(&artifact, &root_path, ControlKind::PrincipalPolicy),
            Err(ControlError::ArtifactHashMismatch { .. })
        ));
    }
}
