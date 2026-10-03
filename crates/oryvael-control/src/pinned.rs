#![forbid(unsafe_code)]

#[path = "lib.rs"]
mod inner;

pub use inner::*;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(1);
const SNAPSHOT_ROOT: &str = "oryvael-pinned";
const CONTROL_SIGNATURE_DOMAIN_PINNED: &[u8] = b"ORYVAEL-CONTROL-V1";

#[derive(Debug, Clone)]
pub struct VerifiedControlArtifact {
    verified: VerifiedControl,
    artifact_path: PathBuf,
    artifact_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
}

impl VerifiedControlArtifact {
    pub fn verified(&self) -> &VerifiedControl {
        &self.verified
    }

    pub fn path(&self) -> &Path {
        &self.artifact_path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }

    pub fn pin_snapshot(&self, label: &str) -> Result<PinnedFile, ControlError> {
        self.pin_snapshot_with_siblings(label, &[])
    }

    pub fn pin_snapshot_with_siblings(
        &self,
        label: &str,
        siblings: &[SnapshotFile],
    ) -> Result<PinnedFile, ControlError> {
        let file_name = self
            .artifact_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("control.json");
        let mut files = Vec::with_capacity(siblings.len() + 1);
        files.push(SnapshotFile {
            file_name: signature_sidecar_path(Path::new(file_name))
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("control.json.control.json")
                .to_owned(),
            bytes: self.signature_bytes.clone(),
        });
        files.extend_from_slice(siblings);
        pin_snapshot(label, file_name, &self.artifact_bytes, &files)
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotFile {
    pub file_name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct PinnedFile {
    directory: PathBuf,
    path: PathBuf,
}

impl PinnedFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PinnedFile {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

pub fn load_verified_from_env(
    artifact_path: impl AsRef<Path>,
    kind: ControlKind,
) -> Result<VerifiedControlArtifact, ControlError> {
    let root = env::var(ROOT_POLICY_ENV).unwrap_or_else(|_| DEFAULT_ROOT_POLICY.into());
    if !Path::new(&root).is_file() {
        return Err(ControlError::MissingRootPolicy(root));
    }
    load_verified_from_files(artifact_path, root, kind)
}

pub fn load_verified_from_files(
    artifact_path: impl AsRef<Path>,
    root_policy_path: impl AsRef<Path>,
    kind: ControlKind,
) -> Result<VerifiedControlArtifact, ControlError> {
    let artifact_path = canonical_file_pinned(artifact_path.as_ref())?;
    let root_policy_path = canonical_file_pinned(root_policy_path.as_ref())?;
    let signature_path = canonical_file_pinned(&signature_sidecar_path(&artifact_path))?;

    let artifact_bytes = fs::read(&artifact_path)?;
    let root_policy_bytes = fs::read(&root_policy_path)?;
    let signature_bytes = fs::read(&signature_path)?;

    let policy: RootTrustPolicy = serde_json::from_slice(&root_policy_bytes)?;
    let statement: ControlSignature = serde_json::from_slice(&signature_bytes)?;
    validate_root_policy_pinned(&policy)?;

    if let Some(minimum) = minimum_root_epoch_pinned()? {
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

    let artifact_sha256 = sha256_hex_pinned(&artifact_bytes);
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

    let public_bytes = decode_fixed_pinned::<32>(&signer.public_key_hex).map_err(|_| {
        ControlError::InvalidPublicKey {
            id: signer.id.clone(),
            key_version: signer.key_version,
        }
    })?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_bytes).map_err(|_| ControlError::InvalidPublicKey {
            id: signer.id.clone(),
            key_version: signer.key_version,
        })?;
    let signature_bytes_raw =
        decode_fixed_pinned::<64>(&statement.signature_hex).map_err(|_| {
            ControlError::InvalidSignatureLength {
                id: signer.id.clone(),
                key_version: signer.key_version,
            }
        })?;
    let signature = Signature::from_bytes(&signature_bytes_raw);
    let payload = signature_payload_pinned(
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

    let verified = VerifiedControl {
        kind,
        signer_id: signer.id.clone(),
        key_version: signer.key_version,
        artifact_sha256: statement.artifact_sha256,
        root_policy_sha256: sha256_hex_pinned(&root_policy_bytes),
        signature_sha256: sha256_hex_pinned(&signature_bytes),
        root_policy_epoch: policy.epoch,
        root_policy_path,
        signature_path,
    };

    Ok(VerifiedControlArtifact {
        verified,
        artifact_path,
        artifact_bytes,
        signature_bytes,
    })
}

pub fn pin_bytes(label: &str, file_name: &str, bytes: &[u8]) -> Result<PinnedFile, ControlError> {
    pin_snapshot(label, file_name, bytes, &[])
}

fn pin_snapshot(
    label: &str,
    file_name: &str,
    bytes: &[u8],
    siblings: &[SnapshotFile],
) -> Result<PinnedFile, ControlError> {
    let file_name = safe_file_name(file_name);
    let directory = create_snapshot_directory(label)?;
    let path = directory.join(&file_name);
    write_snapshot_file(&path, bytes)?;

    for sibling in siblings {
        let sibling_name = safe_file_name(&sibling.file_name);
        write_snapshot_file(&directory.join(sibling_name), &sibling.bytes)?;
    }

    #[cfg(unix)]
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))?;

    Ok(PinnedFile { directory, path })
}

fn create_snapshot_directory(label: &str) -> Result<PathBuf, ControlError> {
    let root = env::temp_dir().join(SNAPSHOT_ROOT);
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;

    for _ in 0..64 {
        let counter = SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = root.join(format!(
            "{}-{}-{nanos:x}-{counter:x}",
            safe_label(label),
            std::process::id()
        ));
        match fs::create_dir(&directory) {
            Ok(()) => {
                #[cfg(unix)]
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
                return Ok(directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ControlError::Io(error)),
        }
    }

    Err(ControlError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "unable to allocate unique pinned snapshot directory",
    )))
}

fn write_snapshot_file(path: &Path, bytes: &[u8]) -> Result<(), ControlError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

fn safe_file_name(value: &str) -> String {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("snapshot.json")
        .to_owned()
}

fn safe_label(value: &str) -> String {
    let normalized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if normalized.is_empty() {
        "control".into()
    } else {
        normalized
    }
}

fn minimum_root_epoch_pinned() -> Result<Option<u64>, ControlError> {
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

fn validate_root_policy_pinned(policy: &RootTrustPolicy) -> Result<(), ControlError> {
    if policy.version != 1 {
        return Err(ControlError::UnsupportedRootVersion(policy.version));
    }
    let mut identities = std::collections::BTreeSet::new();
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

fn signature_payload_pinned(
    kind: ControlKind,
    signer_id: &str,
    key_version: u64,
    artifact_sha256: &str,
) -> Vec<u8> {
    let key_version = key_version.to_string();
    let mut payload = Vec::new();
    for part in [
        CONTROL_SIGNATURE_DOMAIN_PINNED,
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

fn canonical_file_pinned(path: &Path) -> Result<PathBuf, ControlError> {
    let path = fs::canonicalize(path)?;
    if !path.is_file() {
        return Err(ControlError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("not a file: {}", path.display()),
        )));
    }
    Ok(path)
}

fn decode_fixed_pinned<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let decoded = hex::decode(value)?;
    decoded
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}

fn sha256_hex_pinned(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod pinned_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = env::temp_dir().join(format!("oryvael-pinned-test-{label}-{nonce}"));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn verified_bytes_remain_pinned_after_source_replacement() {
        let dir = temp_dir("replacement");
        let artifact = dir.join("plan.json");
        let root = dir.join("root.json");
        let private_key = dir.join("private.hex");
        let original = b"{\"id\":\"CHG-PINNED\"}\n";
        fs::write(&artifact, original).expect("artifact");
        fs::write(&private_key, hex::encode([11_u8; 32])).expect("private key");

        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let policy = RootTrustPolicy {
            version: 1,
            epoch: u64::MAX,
            signers: vec![RootSigner {
                id: "root/test".into(),
                key_version: 1,
                public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
                status: SignerStatus::Active,
                allowed_kinds: vec![ControlKind::ChangePlan],
            }],
        };
        fs::write(&root, serde_json::to_vec(&policy).expect("policy")).expect("root");

        let signature = sign_from_files(
            &private_key,
            "root/test",
            1,
            ControlKind::ChangePlan,
            &artifact,
        )
        .expect("signature");
        fs::write(
            signature_sidecar_path(&artifact),
            serde_json::to_vec(&signature).expect("signature json"),
        )
        .expect("signature sidecar");

        let verified = load_verified_from_files(&artifact, &root, ControlKind::ChangePlan)
            .expect("verified artifact");
        fs::write(&artifact, b"{\"id\":\"CHG-REPLACED\"}\n").expect("replace source");

        assert_eq!(verified.bytes(), original);
        assert!(verify_from_files(&artifact, &root, ControlKind::ChangePlan).is_err());

        let pinned = verified.pin_snapshot("plan").expect("pinned snapshot");
        assert_eq!(fs::read(pinned.path()).expect("pinned bytes"), original);
        let pinned_verified = verify_from_files(pinned.path(), &root, ControlKind::ChangePlan)
            .expect("pinned snapshot verifies");
        assert_eq!(
            pinned_verified.artifact_sha256,
            verified.verified().artifact_sha256
        );
    }
}
