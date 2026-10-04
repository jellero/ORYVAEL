#![forbid(unsafe_code)]

use crate::{JobResult, JobSpec, run_job};
use oryvael_audit::{AuditError, JsonlAuditJournal};
use oryvael_control::{
    ControlError, ControlKind, DEFAULT_ROOT_POLICY, DEFAULT_ROOT_POLICY_MIN_EPOCH, PinnedFile,
    RootTrustPolicy, VerifiedControl, VerifiedControlArtifact, load_verified_from_files, pin_bytes,
};
use oryvael_protocol::{AuditDecision, AuditEvent, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const DEFAULT_SERVICE_SOCKET: &str = "/run/oryvael/trusted.sock";
pub const DEFAULT_SERVICE_AUDIT: &str = "/var/lib/oryvael/audit/trusted-service.jsonl";
const SERVICE_ACTOR: &str = "service/oryvael-trusted";
const SERVICE_VERSION: &str = "oryvael-trusted-service/1";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub socket_path: PathBuf,
    pub root_policy_path: PathBuf,
    pub minimum_epoch_path: PathBuf,
    pub audit_path: PathBuf,
}

impl ServiceConfig {
    pub fn system_defaults() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SERVICE_SOCKET),
            root_policy_path: PathBuf::from(DEFAULT_ROOT_POLICY),
            minimum_epoch_path: PathBuf::from(DEFAULT_ROOT_POLICY_MIN_EPOCH),
            audit_path: PathBuf::from(DEFAULT_SERVICE_AUDIT),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceStatus {
    pub version: String,
    pub instance_id: String,
    pub pid: u32,
    pub socket_path: PathBuf,
    pub root_policy_source: PathBuf,
    pub root_policy_epoch: u64,
    pub root_policy_sha256: String,
    pub minimum_epoch: u64,
    pub audit_path: PathBuf,
    pub audit_records: u64,
    #[serde(default)]
    pub audit_head_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum ServiceRequest {
    Status,
    Verify {
        artifact: PathBuf,
        kind: ControlKind,
    },
    Supervise {
        principal: PathBuf,
        job: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum ServiceResponse {
    Status { status: ServiceStatus },
    Verified { control: VerifiedControl },
    Supervised { result: JobResult },
    Error { code: String, message: String },
}

impl ServiceResponse {
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("control error: {0}")]
    Control(#[from] ControlError),
    #[error("audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid root policy: {0}")]
    InvalidRootPolicy(String),
    #[error("invalid minimum root epoch in {path}: {value}")]
    InvalidMinimumEpoch { path: PathBuf, value: String },
    #[error("root trust policy epoch {actual} is below persistent minimum {minimum}")]
    RootEpochRollback { actual: u64, minimum: u64 },
    #[error("service socket already exists: {0}")]
    SocketExists(PathBuf),
    #[error("invalid service request: {0}")]
    Protocol(String),
}

struct RootOwner {
    source_path: PathBuf,
    policy: RootTrustPolicy,
    policy_sha256: String,
    minimum_epoch: u64,
    snapshot: PinnedFile,
}

impl RootOwner {
    fn load(root_policy_path: &Path, minimum_epoch_path: &Path) -> Result<Self, ServiceError> {
        let source_path = canonical_file(root_policy_path)?;
        let root_bytes = fs::read(&source_path)?;
        let policy: RootTrustPolicy = serde_json::from_slice(&root_bytes)?;
        validate_root_policy(&policy)?;

        let minimum_epoch = read_minimum_epoch(minimum_epoch_path)?;
        if policy.epoch < minimum_epoch {
            return Err(ServiceError::RootEpochRollback {
                actual: policy.epoch,
                minimum: minimum_epoch,
            });
        }
        persist_minimum_epoch(minimum_epoch_path, policy.epoch)?;

        let file_name = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("root-policy.json");
        let snapshot = pin_bytes("trusted-root-policy", file_name, &root_bytes)?;

        Ok(Self {
            source_path,
            policy_sha256: sha256_hex(&root_bytes),
            minimum_epoch: policy.epoch,
            policy,
            snapshot,
        })
    }

    fn verify(
        &self,
        artifact: impl AsRef<Path>,
        kind: ControlKind,
    ) -> Result<VerifiedControlArtifact, ControlError> {
        load_verified_from_files(artifact, self.snapshot.path(), kind)
    }
}

pub struct TrustedService {
    config: ServiceConfig,
    root: RootOwner,
    audit: JsonlAuditJournal,
    instance_id: String,
}

impl TrustedService {
    pub fn open(config: ServiceConfig) -> Result<Self, ServiceError> {
        let root = RootOwner::load(&config.root_policy_path, &config.minimum_epoch_path)?;
        let audit = JsonlAuditJournal::open(&config.audit_path)?;
        Ok(Self {
            config,
            root,
            audit,
            instance_id: new_instance_id(),
        })
    }

    pub fn status(&self) -> ServiceStatus {
        let records = self.audit.records();
        ServiceStatus {
            version: SERVICE_VERSION.into(),
            instance_id: self.instance_id.clone(),
            pid: std::process::id(),
            socket_path: self.config.socket_path.clone(),
            root_policy_source: self.root.source_path.clone(),
            root_policy_epoch: self.root.policy.epoch,
            root_policy_sha256: self.root.policy_sha256.clone(),
            minimum_epoch: self.root.minimum_epoch,
            audit_path: self.config.audit_path.clone(),
            audit_records: records.len() as u64,
            audit_head_sha256: records.last().map(|record| record.hash.clone()),
        }
    }

    pub fn serve(mut self, max_requests: Option<usize>) -> Result<(), ServiceError> {
        let listener = bind_socket(&self.config.socket_path)?;
        let _guard = SocketGuard {
            path: self.config.socket_path.clone(),
        };

        self.append_service_event(
            "service.started",
            self.config.socket_path.to_string_lossy().into_owned(),
            AuditDecision::Observed,
            BTreeMap::from([
                ("instance_id".into(), self.instance_id.clone()),
                ("root_policy_sha256".into(), self.root.policy_sha256.clone()),
                (
                    "root_policy_epoch".into(),
                    self.root.policy.epoch.to_string(),
                ),
                ("minimum_epoch".into(), self.root.minimum_epoch.to_string()),
            ]),
        )?;

        for (index, connection) in listener.incoming().enumerate() {
            let stream = connection?;
            self.serve_connection(stream)?;
            let served = index + 1;
            if max_requests.is_some_and(|limit| served >= limit) {
                break;
            }
        }

        self.append_service_event(
            "service.stopped",
            self.config.socket_path.to_string_lossy().into_owned(),
            AuditDecision::Observed,
            BTreeMap::from([("instance_id".into(), self.instance_id.clone())]),
        )?;
        Ok(())
    }

    fn serve_connection(&mut self, mut stream: UnixStream) -> Result<(), ServiceError> {
        let request = match read_request(&mut stream) {
            Ok(request) => request,
            Err(error) => {
                write_response(
                    &mut stream,
                    &ServiceResponse::Error {
                        code: "invalid_request".into(),
                        message: error.to_string(),
                    },
                )?;
                return Ok(());
            }
        };

        let response = self.handle_request(request)?;
        write_response(&mut stream, &response)?;
        Ok(())
    }

    fn handle_request(&mut self, request: ServiceRequest) -> Result<ServiceResponse, ServiceError> {
        match request {
            ServiceRequest::Status => Ok(ServiceResponse::Status {
                status: self.status(),
            }),
            ServiceRequest::Verify { artifact, kind } => self.handle_verify(artifact, kind),
            ServiceRequest::Supervise { principal, job } => self.handle_supervise(principal, job),
        }
    }

    fn handle_verify(
        &mut self,
        artifact: PathBuf,
        kind: ControlKind,
    ) -> Result<ServiceResponse, ServiceError> {
        match self.root.verify(&artifact, kind) {
            Ok(verified) => {
                let control = verified.verified().clone();
                self.append_service_event(
                    "control.verify",
                    artifact.to_string_lossy().into_owned(),
                    AuditDecision::Allowed,
                    BTreeMap::from([
                        ("kind".into(), kind.as_str().into()),
                        ("signer_id".into(), control.signer_id.clone()),
                        ("key_version".into(), control.key_version.to_string()),
                        ("artifact_sha256".into(), control.artifact_sha256.clone()),
                        ("root_policy_sha256".into(), self.root.policy_sha256.clone()),
                        (
                            "root_policy_epoch".into(),
                            self.root.policy.epoch.to_string(),
                        ),
                    ]),
                )?;
                Ok(ServiceResponse::Verified { control })
            }
            Err(error) => {
                self.append_service_event(
                    "control.verify",
                    artifact.to_string_lossy().into_owned(),
                    AuditDecision::Denied,
                    BTreeMap::from([
                        ("kind".into(), kind.as_str().into()),
                        ("error".into(), error.to_string()),
                        ("root_policy_sha256".into(), self.root.policy_sha256.clone()),
                    ]),
                )?;
                Ok(ServiceResponse::Error {
                    code: "control_verification_failed".into(),
                    message: error.to_string(),
                })
            }
        }
    }

    fn handle_supervise(
        &mut self,
        principal_path: PathBuf,
        job_path: PathBuf,
    ) -> Result<ServiceResponse, ServiceError> {
        let verified = match self
            .root
            .verify(&principal_path, ControlKind::PrincipalPolicy)
        {
            Ok(verified) => verified,
            Err(error) => {
                self.append_service_event(
                    "control.verify",
                    principal_path.to_string_lossy().into_owned(),
                    AuditDecision::Denied,
                    BTreeMap::from([
                        ("kind".into(), ControlKind::PrincipalPolicy.as_str().into()),
                        ("error".into(), error.to_string()),
                    ]),
                )?;
                return Ok(ServiceResponse::Error {
                    code: "principal_verification_failed".into(),
                    message: error.to_string(),
                });
            }
        };

        let control = verified.verified().clone();
        self.append_service_event(
            "control.verify",
            principal_path.to_string_lossy().into_owned(),
            AuditDecision::Allowed,
            BTreeMap::from([
                ("kind".into(), ControlKind::PrincipalPolicy.as_str().into()),
                ("signer_id".into(), control.signer_id.clone()),
                ("artifact_sha256".into(), control.artifact_sha256.clone()),
            ]),
        )?;

        let principal: Principal = match serde_json::from_slice(verified.bytes()) {
            Ok(principal) => principal,
            Err(error) => {
                return self.supervise_error(
                    SERVICE_ACTOR,
                    &job_path,
                    "invalid_principal_policy",
                    error.to_string(),
                );
            }
        };

        let job_bytes = match fs::read(&job_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return self.supervise_error(
                    &principal.principal,
                    &job_path,
                    "job_read_failed",
                    error.to_string(),
                );
            }
        };
        let mut spec: JobSpec = match serde_json::from_slice(&job_bytes) {
            Ok(spec) => spec,
            Err(error) => {
                return self.supervise_error(
                    &principal.principal,
                    &job_path,
                    "invalid_job_spec",
                    error.to_string(),
                );
            }
        };

        spec.audit_context
            .insert("trusted_service".into(), SERVICE_VERSION.into());
        spec.audit_context
            .insert("trusted_service_instance".into(), self.instance_id.clone());
        spec.audit_context.insert(
            "service_root_policy_sha256".into(),
            self.root.policy_sha256.clone(),
        );
        spec.audit_context.insert(
            "service_root_policy_epoch".into(),
            self.root.policy.epoch.to_string(),
        );
        spec.audit_context.insert(
            "principal_policy_sha256".into(),
            control.artifact_sha256.clone(),
        );
        spec.audit_context
            .insert("service_job_sha256".into(), sha256_hex(&job_bytes));

        self.append_service_event(
            "service.supervise.start",
            spec.workspace.to_string_lossy().into_owned(),
            AuditDecision::Observed,
            BTreeMap::from([
                ("principal".into(), principal.principal.clone()),
                ("change_id".into(), spec.change_id.clone()),
                ("job_sha256".into(), sha256_hex(&job_bytes)),
                ("principal_policy_sha256".into(), control.artifact_sha256),
            ]),
        )?;

        match run_job(principal.clone(), spec) {
            Ok(result) => {
                let decision = if result.success {
                    AuditDecision::Allowed
                } else {
                    AuditDecision::Failed
                };
                let mut metadata = BTreeMap::from([
                    ("principal".into(), principal.principal),
                    ("operation_id".into(), result.operation_id.clone()),
                    ("timed_out".into(), result.timed_out.to_string()),
                ]);
                if let Some(exit_code) = result.exit_code {
                    metadata.insert("exit_code".into(), exit_code.to_string());
                }
                self.append_service_event(
                    "service.supervise.complete",
                    job_path.to_string_lossy().into_owned(),
                    decision,
                    metadata,
                )?;
                Ok(ServiceResponse::Supervised { result })
            }
            Err(error) => self.supervise_error(
                &principal.principal,
                &job_path,
                "supervisor_failed",
                error.to_string(),
            ),
        }
    }

    fn supervise_error(
        &mut self,
        actor: &str,
        job_path: &Path,
        code: &str,
        message: String,
    ) -> Result<ServiceResponse, ServiceError> {
        self.append_service_event(
            "service.supervise.failed",
            job_path.to_string_lossy().into_owned(),
            AuditDecision::Failed,
            BTreeMap::from([
                ("actor".into(), actor.into()),
                ("error_code".into(), code.into()),
                ("error".into(), message.clone()),
            ]),
        )?;
        Ok(ServiceResponse::Error {
            code: code.into(),
            message,
        })
    }

    fn append_service_event(
        &mut self,
        action: &str,
        target: String,
        decision: AuditDecision,
        mut metadata: BTreeMap<String, String>,
    ) -> Result<(), ServiceError> {
        metadata.insert("service_version".into(), SERVICE_VERSION.into());
        metadata.insert("instance_id".into(), self.instance_id.clone());
        self.audit.append(AuditEvent {
            timestamp_ns: now_ns(),
            actor: SERVICE_ACTOR.into(),
            action: action.into(),
            target,
            decision,
            change_id: None,
            operation_id: None,
            metadata,
        })?;
        Ok(())
    }
}

pub fn request(
    socket_path: impl AsRef<Path>,
    request: &ServiceRequest,
) -> Result<ServiceResponse, ServiceError> {
    let mut stream = UnixStream::connect(socket_path)?;
    let payload = serde_json::to_vec(request)?;
    if payload.len() as u64 > MAX_REQUEST_BYTES {
        return Err(ServiceError::Protocol("request exceeds size limit".into()));
    }
    stream.write_all(&payload)?;
    stream.shutdown(Shutdown::Write)?;

    let mut response_bytes = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response_bytes)?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ServiceError::Protocol("response exceeds size limit".into()));
    }
    Ok(serde_json::from_slice(&response_bytes)?)
}

fn read_request(stream: &mut UnixStream) -> Result<ServiceRequest, ServiceError> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut bytes = Vec::new();
    stream.take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(ServiceError::Protocol("request exceeds size limit".into()));
    }
    if bytes.is_empty() {
        return Err(ServiceError::Protocol("empty request".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_response(stream: &mut UnixStream, response: &ServiceResponse) -> Result<(), ServiceError> {
    let bytes = serde_json::to_vec(response)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ServiceError::Protocol("response exceeds size limit".into()));
    }
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn bind_socket(path: &Path) -> Result<UnixListener, ServiceError> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_socket() {
            return Err(ServiceError::SocketExists(path.to_path_buf()));
        }
        return Err(ServiceError::Protocol(format!(
            "refusing to replace non-socket path: {}",
            path.display()
        )));
    }
    if let Some(parent) = nonempty_parent(path) {
        fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn canonical_file(path: &Path) -> Result<PathBuf, ServiceError> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_file() {
        return Err(ServiceError::InvalidRootPolicy(format!(
            "not a file: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn validate_root_policy(policy: &RootTrustPolicy) -> Result<(), ServiceError> {
    if policy.version != 1 {
        return Err(ServiceError::InvalidRootPolicy(format!(
            "unsupported version {}",
            policy.version
        )));
    }
    let mut identities = BTreeSet::new();
    for signer in &policy.signers {
        if !identities.insert((signer.id.as_str(), signer.key_version)) {
            return Err(ServiceError::InvalidRootPolicy(format!(
                "duplicate signer {}@{}",
                signer.id, signer.key_version
            )));
        }
    }
    Ok(())
}

fn read_minimum_epoch(path: &Path) -> Result<u64, ServiceError> {
    if !path.exists() {
        return Ok(0);
    }
    let raw = fs::read_to_string(path)?;
    raw.trim()
        .parse::<u64>()
        .map_err(|_| ServiceError::InvalidMinimumEpoch {
            path: path.to_path_buf(),
            value: raw,
        })
}

fn persist_minimum_epoch(path: &Path, epoch: u64) -> Result<(), ServiceError> {
    let current = read_minimum_epoch(path)?;
    if epoch < current {
        return Err(ServiceError::RootEpochRollback {
            actual: epoch,
            minimum: current,
        });
    }
    if epoch == current {
        return Ok(());
    }

    if let Some(parent) = nonempty_parent(path) {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("root-policy.min-epoch");
    let temporary = path.with_file_name(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        now_ns()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    writeln!(file, "{epoch}")?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = nonempty_parent(path) {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn nonempty_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn new_instance_id() -> String {
    format!("SVC-{}-{}", std::process::id(), now_ns())
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryvael_audit::load_jsonl;
    use oryvael_control::{
        RootSigner, SignerStatus, public_key_from_private_file, sign_from_files,
        signature_sidecar_path,
    };
    use oryvael_protocol::{Principal, PrincipalKind};
    use std::thread;

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "oryvael-service-{label}-{}-{}",
            std::process::id(),
            now_ns()
        ));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn write_root(dir: &Path, epoch: u64, status: SignerStatus) -> (PathBuf, PathBuf) {
        let key_path = dir.join("root-key.hex");
        fs::write(&key_path, hex::encode([7_u8; 32])).expect("key");
        let public_key_hex = public_key_from_private_file(&key_path).expect("public key");
        let root = RootTrustPolicy {
            version: 1,
            epoch,
            signers: vec![RootSigner {
                id: "root/test".into(),
                key_version: 1,
                public_key_hex,
                status,
                allowed_kinds: vec![ControlKind::PrincipalPolicy],
            }],
        };
        let root_path = dir.join("root-policy.json");
        fs::write(&root_path, serde_json::to_vec(&root).expect("root json")).expect("root");
        (root_path, key_path)
    }

    fn write_signed_principal(dir: &Path, key_path: &Path) -> PathBuf {
        let principal = Principal {
            principal: "developer-ai/test".into(),
            kind: PrincipalKind::AiAgent,
            grants: vec![],
        };
        let path = dir.join("principal.json");
        fs::write(
            &path,
            serde_json::to_vec(&principal).expect("principal json"),
        )
        .expect("principal");
        let signature = sign_from_files(
            key_path,
            "root/test",
            1,
            ControlKind::PrincipalPolicy,
            &path,
        )
        .expect("signature");
        fs::write(
            signature_sidecar_path(&path),
            serde_json::to_vec(&signature).expect("signature json"),
        )
        .expect("sidecar");
        path
    }

    fn config(dir: &Path, root_policy_path: PathBuf) -> ServiceConfig {
        ServiceConfig {
            socket_path: dir.join("trusted.sock"),
            root_policy_path,
            minimum_epoch_path: dir.join("minimum-epoch"),
            audit_path: dir.join("trusted-audit.jsonl"),
        }
    }

    fn wait_for_socket(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("socket was not created: {}", path.display());
    }

    #[test]
    fn epoch_persists_across_restart_and_blocks_rollback() {
        let dir = temp_dir("epoch");
        let (root_path, _) = write_root(&dir, 2, SignerStatus::Active);
        let service_config = config(&dir, root_path.clone());
        let service = TrustedService::open(service_config.clone()).expect("service epoch 2");
        assert_eq!(service.status().minimum_epoch, 2);
        drop(service);
        assert_eq!(
            fs::read_to_string(&service_config.minimum_epoch_path).unwrap(),
            "2\n"
        );

        let root: RootTrustPolicy =
            serde_json::from_slice(&fs::read(&root_path).expect("root bytes")).unwrap();
        let mut advanced = root.clone();
        advanced.epoch = 3;
        fs::write(&root_path, serde_json::to_vec(&advanced).unwrap()).unwrap();
        let service = TrustedService::open(service_config.clone()).expect("service epoch 3");
        assert_eq!(service.status().minimum_epoch, 3);
        drop(service);

        fs::write(&root_path, serde_json::to_vec(&root).unwrap()).unwrap();
        assert!(matches!(
            TrustedService::open(service_config),
            Err(ServiceError::RootEpochRollback {
                actual: 2,
                minimum: 3
            })
        ));
    }

    #[test]
    fn unix_service_verifies_with_pinned_root_and_persists_audit() {
        let dir = temp_dir("socket");
        let (root_path, key_path) = write_root(&dir, 4, SignerStatus::Active);
        let principal_path = write_signed_principal(&dir, &key_path);
        let service_config = config(&dir, root_path.clone());
        let socket = service_config.socket_path.clone();
        let audit_path = service_config.audit_path.clone();

        let service = TrustedService::open(service_config).expect("service");
        let handle = std::thread::spawn(move || service.serve(Some(2)));
        wait_for_socket(&socket);

        let status = request(&socket, &ServiceRequest::Status).expect("status");
        assert!(matches!(status, ServiceResponse::Status { .. }));

        let verified = request(
            &socket,
            &ServiceRequest::Verify {
                artifact: principal_path,
                kind: ControlKind::PrincipalPolicy,
            },
        )
        .expect("verify");
        assert!(matches!(verified, ServiceResponse::Verified { .. }));
        handle.join().expect("thread").expect("serve");

        let ledger = load_jsonl(&audit_path).expect("audit");
        let actions = ledger
            .records()
            .iter()
            .map(|record| record.event.action.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec!["service.started", "control.verify", "service.stopped"]
        );
    }

    #[test]
    fn running_service_keeps_root_snapshot_until_controlled_restart() {
        let dir = temp_dir("root-snapshot");
        let (root_path, key_path) = write_root(&dir, 7, SignerStatus::Active);
        let principal_path = write_signed_principal(&dir, &key_path);
        let service_config = config(&dir, root_path.clone());
        let socket = service_config.socket_path.clone();

        let service = TrustedService::open(service_config.clone()).expect("service");
        let handle = std::thread::spawn(move || service.serve(Some(1)));
        wait_for_socket(&socket);

        let root: RootTrustPolicy =
            serde_json::from_slice(&fs::read(&root_path).expect("root bytes")).unwrap();
        let mut revoked = root;
        revoked.signers[0].status = SignerStatus::Revoked;
        fs::write(&root_path, serde_json::to_vec(&revoked).unwrap()).unwrap();

        let response = request(
            &socket,
            &ServiceRequest::Verify {
                artifact: principal_path.clone(),
                kind: ControlKind::PrincipalPolicy,
            },
        )
        .expect("request");
        assert!(matches!(response, ServiceResponse::Verified { .. }));
        handle.join().expect("thread").expect("serve");

        let service = TrustedService::open(service_config).expect("restart with revoked root");
        let result = service
            .root
            .verify(&principal_path, ControlKind::PrincipalPolicy);
        assert!(matches!(result, Err(ControlError::RevokedSigner { .. })));
    }
}
