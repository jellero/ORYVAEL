#![forbid(unsafe_code)]

use crate::peercred::{PeerProcess, peer_process};
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
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const DEFAULT_SERVICE_SOCKET: &str = "/run/oryvael/trusted.sock";
pub const DEFAULT_SERVICE_AUDIT: &str = "/var/lib/oryvael/audit/trusted-service.jsonl";
pub const DEFAULT_PEER_POLICY: &str = "/etc/oryvael/peer-policy.json";
const SERVICE_ACTOR: &str = "service/oryvael-trusted";
const SERVICE_VERSION: &str = "oryvael-trusted-service/3";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub socket_path: PathBuf,
    pub root_policy_path: PathBuf,
    pub minimum_epoch_path: PathBuf,
    pub peer_policy_path: PathBuf,
    pub audit_path: PathBuf,
}

impl ServiceConfig {
    pub fn system_defaults() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SERVICE_SOCKET),
            root_policy_path: PathBuf::from(DEFAULT_ROOT_POLICY),
            minimum_epoch_path: PathBuf::from(DEFAULT_ROOT_POLICY_MIN_EPOCH),
            peer_policy_path: PathBuf::from(DEFAULT_PEER_POLICY),
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
    pub peer_policy_source: PathBuf,
    pub peer_policy_sha256: String,
    pub peer_bindings: u64,
    pub audit_path: PathBuf,
    pub audit_records: u64,
    #[serde(default)]
    pub audit_head_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PeerOperation {
    Status,
    Verify,
    Supervise,
}

impl PeerOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Verify => "verify",
            Self::Supervise => "supervise",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerBinding {
    pub id: String,
    pub uid: u32,
    pub gid: u32,
    pub executable_sha256: String,
    pub operations: Vec<PeerOperation>,
    #[serde(default)]
    pub principals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicy {
    pub version: u32,
    pub bindings: Vec<PeerBinding>,
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

impl ServiceRequest {
    fn operation(&self) -> PeerOperation {
        match self {
            Self::Status => PeerOperation::Status,
            Self::Verify { .. } => PeerOperation::Verify,
            Self::Supervise { .. } => PeerOperation::Supervise,
        }
    }
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
    #[error("invalid peer policy: {0}")]
    InvalidPeerPolicy(String),
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

struct PeerPolicyOwner {
    source_path: PathBuf,
    policy: PeerPolicy,
    artifact_sha256: String,
    signer_id: String,
    key_version: u64,
}

impl PeerPolicyOwner {
    fn load(root: &RootOwner, peer_policy_path: &Path) -> Result<Self, ServiceError> {
        let verified = root.verify(peer_policy_path, ControlKind::PeerPolicy)?;
        let policy: PeerPolicy = serde_json::from_slice(verified.bytes())?;
        validate_peer_policy(&policy)?;
        let control = verified.verified();
        Ok(Self {
            source_path: verified.path().to_path_buf(),
            policy,
            artifact_sha256: control.artifact_sha256.clone(),
            signer_id: control.signer_id.clone(),
            key_version: control.key_version,
        })
    }

    fn binding_for(&self, peer: &PeerIdentity) -> Option<PeerBinding> {
        self.policy
            .bindings
            .iter()
            .find(|binding| {
                binding.uid == peer.uid
                    && binding.gid == peer.gid
                    && binding.executable_sha256 == peer.executable_sha256
            })
            .cloned()
    }
}

#[derive(Debug)]
struct PeerIdentity {
    pid: u32,
    uid: u32,
    gid: u32,
    executable_path: PathBuf,
    executable_sha256: String,
    process: PeerProcess,
}

impl PeerIdentity {
    fn capture(stream: &UnixStream) -> Result<Self, ServiceError> {
        let process = peer_process(stream)?;
        let credentials = process.credentials();
        let pid = u32::try_from(credentials.pid)
            .map_err(|_| ServiceError::Protocol(format!("invalid peer pid {}", credentials.pid)))?;
        process.ensure_alive()?;

        let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let executable_file = File::open(&proc_exe)?;
        process.ensure_alive()?;

        let stable_exe = PathBuf::from(format!(
            "/proc/self/fd/{}",
            executable_file.as_raw_fd()
        ));
        let executable_path = fs::read_link(&stable_exe)?;
        let executable_sha256 = sha256_file(&stable_exe)?;
        process.ensure_alive()?;

        Ok(Self {
            pid,
            uid: credentials.uid,
            gid: credentials.gid,
            executable_path,
            executable_sha256,
            process,
        })
    }

    fn revalidate_executable(&self) -> Result<(), ServiceError> {
        self.process.ensure_alive()?;
        let proc_exe = PathBuf::from(format!("/proc/{}/exe", self.pid));
        let executable_file = File::open(&proc_exe)?;
        self.process.ensure_alive()?;

        let stable_exe = PathBuf::from(format!(
            "/proc/self/fd/{}",
            executable_file.as_raw_fd()
        ));
        let executable_sha256 = sha256_file(&stable_exe)?;
        self.process.ensure_alive()?;
        if executable_sha256 != self.executable_sha256 {
            return Err(ServiceError::Protocol(
                "peer executable changed after connection authentication".into(),
            ));
        }
        Ok(())
    }
}

pub struct TrustedService {
    config: ServiceConfig,
    root: RootOwner,
    peers: PeerPolicyOwner,
    audit: JsonlAuditJournal,
    instance_id: String,
}

impl TrustedService {
    pub fn open(config: ServiceConfig) -> Result<Self, ServiceError> {
        let root = RootOwner::load(&config.root_policy_path, &config.minimum_epoch_path)?;
        let peers = PeerPolicyOwner::load(&root, &config.peer_policy_path)?;
        let audit = JsonlAuditJournal::open(&config.audit_path)?;
        Ok(Self {
            config,
            root,
            peers,
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
            peer_policy_source: self.peers.source_path.clone(),
            peer_policy_sha256: self.peers.artifact_sha256.clone(),
            peer_bindings: self.peers.policy.bindings.len() as u64,
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
                (
                    "peer_policy_sha256".into(),
                    self.peers.artifact_sha256.clone(),
                ),
                ("peer_policy_signer".into(), self.peers.signer_id.clone()),
                (
                    "peer_policy_key_version".into(),
                    self.peers.key_version.to_string(),
                ),
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
        let peer = match PeerIdentity::capture(&stream) {
            Ok(peer) => peer,
            Err(error) => {
                self.append_service_event(
                    "ipc.peer.credentials_failed",
                    self.config.socket_path.to_string_lossy().into_owned(),
                    AuditDecision::Denied,
                    BTreeMap::from([("error".into(), error.to_string())]),
                )?;
                drain_rejected_request(&mut stream);
                write_response(
                    &mut stream,
                    &ServiceResponse::Error {
                        code: "peer_credentials_unavailable".into(),
                        message: error.to_string(),
                    },
                )?;
                return Ok(());
            }
        };

        let binding = match self.peers.binding_for(&peer) {
            Some(binding) => binding,
            None => {
                self.append_service_event(
                    "ipc.peer.denied",
                    peer.executable_path.to_string_lossy().into_owned(),
                    AuditDecision::Denied,
                    peer_metadata(&peer, None),
                )?;
                drain_rejected_request(&mut stream);
                write_response(
                    &mut stream,
                    &ServiceResponse::Error {
                        code: "peer_authentication_failed".into(),
                        message: "kernel peer identity is not authorized by signed peer policy"
                            .into(),
                    },
                )?;
                return Ok(());
            }
        };

        self.append_service_event(
            "ipc.peer.authenticated",
            peer.executable_path.to_string_lossy().into_owned(),
            AuditDecision::Allowed,
            peer_metadata(&peer, Some(&binding)),
        )?;

        let request = match read_request(&mut stream) {
            Ok(request) => request,
            Err(error) => {
                let mut metadata = peer_metadata(&peer, Some(&binding));
                metadata.insert("error".into(), error.to_string());
                self.append_service_event(
                    "ipc.request.invalid",
                    self.config.socket_path.to_string_lossy().into_owned(),
                    AuditDecision::Denied,
                    metadata,
                )?;
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

        if let Err(error) = peer.revalidate_executable() {
            let mut metadata = peer_metadata(&peer, Some(&binding));
            metadata.insert("error".into(), error.to_string());
            self.append_service_event(
                "ipc.peer.identity_changed",
                binding.id.clone(),
                AuditDecision::Denied,
                metadata,
            )?;
            write_response(
                &mut stream,
                &ServiceResponse::Error {
                    code: "peer_identity_changed".into(),
                    message: error.to_string(),
                },
            )?;
            return Ok(());
        }

        let response = self.handle_request(request, &peer, &binding)?;
        write_response(&mut stream, &response)?;
        Ok(())
    }

    fn handle_request(
        &mut self,
        request: ServiceRequest,
        peer: &PeerIdentity,
        binding: &PeerBinding,
    ) -> Result<ServiceResponse, ServiceError> {
        let operation = request.operation();
        if !binding.operations.contains(&operation) {
            let mut metadata = peer_metadata(peer, Some(binding));
            metadata.insert("operation".into(), operation.as_str().into());
            self.append_service_event(
                "ipc.operation.denied",
                binding.id.clone(),
                AuditDecision::Denied,
                metadata,
            )?;
            return Ok(ServiceResponse::Error {
                code: "peer_operation_denied".into(),
                message: format!(
                    "peer binding {} does not authorize {}",
                    binding.id,
                    operation.as_str()
                ),
            });
        }

        let mut metadata = peer_metadata(peer, Some(binding));
        metadata.insert("operation".into(), operation.as_str().into());
        self.append_service_event(
            "ipc.operation.allowed",
            binding.id.clone(),
            AuditDecision::Allowed,
            metadata,
        )?;

        match request {
            ServiceRequest::Status => Ok(ServiceResponse::Status {
                status: self.status(),
            }),
            ServiceRequest::Verify { artifact, kind } => {
                self.handle_verify(artifact, kind, peer, binding)
            }
            ServiceRequest::Supervise { principal, job } => {
                self.handle_supervise(principal, job, peer, binding)
            }
        }
    }

    fn handle_verify(
        &mut self,
        artifact: PathBuf,
        kind: ControlKind,
        peer: &PeerIdentity,
        binding: &PeerBinding,
    ) -> Result<ServiceResponse, ServiceError> {
        match self.root.verify(&artifact, kind) {
            Ok(verified) => {
                let control = verified.verified().clone();
                let mut metadata = peer_metadata(peer, Some(binding));
                metadata.extend([
                    ("kind".into(), kind.as_str().into()),
                    ("signer_id".into(), control.signer_id.clone()),
                    ("key_version".into(), control.key_version.to_string()),
                    ("artifact_sha256".into(), control.artifact_sha256.clone()),
                    ("root_policy_sha256".into(), self.root.policy_sha256.clone()),
                    (
                        "root_policy_epoch".into(),
                        self.root.policy.epoch.to_string(),
                    ),
                ]);
                self.append_service_event(
                    "control.verify",
                    artifact.to_string_lossy().into_owned(),
                    AuditDecision::Allowed,
                    metadata,
                )?;
                Ok(ServiceResponse::Verified { control })
            }
            Err(error) => {
                let mut metadata = peer_metadata(peer, Some(binding));
                metadata.extend([
                    ("kind".into(), kind.as_str().into()),
                    ("error".into(), error.to_string()),
                    ("root_policy_sha256".into(), self.root.policy_sha256.clone()),
                ]);
                self.append_service_event(
                    "control.verify",
                    artifact.to_string_lossy().into_owned(),
                    AuditDecision::Denied,
                    metadata,
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
        peer: &PeerIdentity,
        binding: &PeerBinding,
    ) -> Result<ServiceResponse, ServiceError> {
        let verified = match self
            .root
            .verify(&principal_path, ControlKind::PrincipalPolicy)
        {
            Ok(verified) => verified,
            Err(error) => {
                let mut metadata = peer_metadata(peer, Some(binding));
                metadata.extend([
                    ("kind".into(), ControlKind::PrincipalPolicy.as_str().into()),
                    ("error".into(), error.to_string()),
                ]);
                self.append_service_event(
                    "control.verify",
                    principal_path.to_string_lossy().into_owned(),
                    AuditDecision::Denied,
                    metadata,
                )?;
                return Ok(ServiceResponse::Error {
                    code: "principal_verification_failed".into(),
                    message: error.to_string(),
                });
            }
        };

        let control = verified.verified().clone();
        let mut verification_metadata = peer_metadata(peer, Some(binding));
        verification_metadata.extend([
            ("kind".into(), ControlKind::PrincipalPolicy.as_str().into()),
            ("signer_id".into(), control.signer_id.clone()),
            ("artifact_sha256".into(), control.artifact_sha256.clone()),
        ]);
        self.append_service_event(
            "control.verify",
            principal_path.to_string_lossy().into_owned(),
            AuditDecision::Allowed,
            verification_metadata,
        )?;

        let principal: Principal = match serde_json::from_slice(verified.bytes()) {
            Ok(principal) => principal,
            Err(error) => {
                return self.supervise_error(
                    SERVICE_ACTOR,
                    &job_path,
                    "invalid_principal_policy",
                    error.to_string(),
                    peer,
                    binding,
                );
            }
        };

        if !binding
            .principals
            .iter()
            .any(|allowed| allowed == &principal.principal)
        {
            let mut metadata = peer_metadata(peer, Some(binding));
            metadata.insert("principal".into(), principal.principal.clone());
            self.append_service_event(
                "ipc.principal.denied",
                binding.id.clone(),
                AuditDecision::Denied,
                metadata,
            )?;
            return Ok(ServiceResponse::Error {
                code: "peer_principal_denied".into(),
                message: format!(
                    "peer binding {} is not authorized for principal {}",
                    binding.id, principal.principal
                ),
            });
        }

        let job_bytes = match fs::read(&job_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return self.supervise_error(
                    &principal.principal,
                    &job_path,
                    "job_read_failed",
                    error.to_string(),
                    peer,
                    binding,
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
                    peer,
                    binding,
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
            "service_peer_policy_sha256".into(),
            self.peers.artifact_sha256.clone(),
        );
        spec.audit_context
            .insert("service_peer_binding".into(), binding.id.clone());
        spec.audit_context
            .insert("service_peer_uid".into(), peer.uid.to_string());
        spec.audit_context
            .insert("service_peer_gid".into(), peer.gid.to_string());
        spec.audit_context
            .insert("service_peer_pid".into(), peer.pid.to_string());
        spec.audit_context.insert(
            "service_peer_executable_sha256".into(),
            peer.executable_sha256.clone(),
        );
        spec.audit_context
            .insert("service_peer_pidfd_bound".into(), "true".into());
        spec.audit_context.insert(
            "principal_policy_sha256".into(),
            control.artifact_sha256.clone(),
        );
        spec.audit_context
            .insert("service_job_sha256".into(), sha256_hex(&job_bytes));

        let mut start_metadata = peer_metadata(peer, Some(binding));
        start_metadata.extend([
            ("principal".into(), principal.principal.clone()),
            ("change_id".into(), spec.change_id.clone()),
            ("job_sha256".into(), sha256_hex(&job_bytes)),
            ("principal_policy_sha256".into(), control.artifact_sha256),
        ]);
        self.append_service_event(
            "service.supervise.start",
            spec.workspace.to_string_lossy().into_owned(),
            AuditDecision::Observed,
            start_metadata,
        )?;

        match run_job(principal.clone(), spec) {
            Ok(result) => {
                let decision = if result.success {
                    AuditDecision::Allowed
                } else {
                    AuditDecision::Failed
                };
                let mut metadata = peer_metadata(peer, Some(binding));
                metadata.extend([
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
                peer,
                binding,
            ),
        }
    }

    fn supervise_error(
        &mut self,
        actor: &str,
        job_path: &Path,
        code: &str,
        message: String,
        peer: &PeerIdentity,
        binding: &PeerBinding,
    ) -> Result<ServiceResponse, ServiceError> {
        let mut metadata = peer_metadata(peer, Some(binding));
        metadata.extend([
            ("actor".into(), actor.into()),
            ("error_code".into(), code.into()),
            ("error".into(), message.clone()),
        ]);
        self.append_service_event(
            "service.supervise.failed",
            job_path.to_string_lossy().into_owned(),
            AuditDecision::Failed,
            metadata,
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
    (&mut *stream)
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(ServiceError::Protocol("request exceeds size limit".into()));
    }
    if bytes.is_empty() {
        return Err(ServiceError::Protocol("empty request".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn drain_rejected_request(stream: &mut UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let mut discarded = Vec::new();
    let _ = (&mut *stream)
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut discarded);
    let _ = stream.shutdown(Shutdown::Read);
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

fn validate_peer_policy(policy: &PeerPolicy) -> Result<(), ServiceError> {
    if policy.version != 1 {
        return Err(ServiceError::InvalidPeerPolicy(format!(
            "unsupported version {}",
            policy.version
        )));
    }
    if policy.bindings.is_empty() {
        return Err(ServiceError::InvalidPeerPolicy(
            "at least one peer binding is required".into(),
        ));
    }

    let mut ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for binding in &policy.bindings {
        if binding.id.trim().is_empty() {
            return Err(ServiceError::InvalidPeerPolicy(
                "peer binding id must not be empty".into(),
            ));
        }
        if !ids.insert(binding.id.as_str()) {
            return Err(ServiceError::InvalidPeerPolicy(format!(
                "duplicate peer binding id: {}",
                binding.id
            )));
        }
        if binding.operations.is_empty() {
            return Err(ServiceError::InvalidPeerPolicy(format!(
                "peer binding {} has no authorized operations",
                binding.id
            )));
        }
        if !is_lower_hex_sha256(&binding.executable_sha256) {
            return Err(ServiceError::InvalidPeerPolicy(format!(
                "peer binding {} has invalid executable_sha256",
                binding.id
            )));
        }
        if !identities.insert((binding.uid, binding.gid, binding.executable_sha256.as_str())) {
            return Err(ServiceError::InvalidPeerPolicy(format!(
                "duplicate peer identity in binding {}",
                binding.id
            )));
        }
        if binding.operations.contains(&PeerOperation::Supervise) && binding.principals.is_empty() {
            return Err(ServiceError::InvalidPeerPolicy(format!(
                "peer binding {} authorizes supervise but no principals",
                binding.id
            )));
        }
        let mut operations = BTreeSet::new();
        for operation in &binding.operations {
            if !operations.insert(*operation) {
                return Err(ServiceError::InvalidPeerPolicy(format!(
                    "peer binding {} repeats operation {}",
                    binding.id,
                    operation.as_str()
                )));
            }
        }
        let mut principals = BTreeSet::new();
        for principal in &binding.principals {
            if principal.trim().is_empty() || !principals.insert(principal.as_str()) {
                return Err(ServiceError::InvalidPeerPolicy(format!(
                    "peer binding {} contains invalid or duplicate principal",
                    binding.id
                )));
            }
        }
    }
    Ok(())
}

fn peer_metadata(peer: &PeerIdentity, binding: Option<&PeerBinding>) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::from([
        ("peer_pid".into(), peer.pid.to_string()),
        ("peer_uid".into(), peer.uid.to_string()),
        ("peer_gid".into(), peer.gid.to_string()),
        ("peer_pidfd_bound".into(), "true".into()),
        (
            "peer_executable".into(),
            peer.executable_path.to_string_lossy().into_owned(),
        ),
        (
            "peer_executable_sha256".into(),
            peer.executable_sha256.clone(),
        ),
    ]);
    if let Some(binding) = binding {
        metadata.insert("peer_binding".into(), binding.id.clone());
    }
    metadata
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_file(path: &Path) -> Result<String, ServiceError> {
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

    fn current_peer_identity() -> PeerIdentity {
        let (left, _right) = UnixStream::pair().expect("pair");
        PeerIdentity::capture(&left).expect("peer identity")
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
                allowed_kinds: vec![ControlKind::PrincipalPolicy, ControlKind::PeerPolicy],
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

    fn write_peer_policy(
        dir: &Path,
        key_path: &Path,
        operations: Vec<PeerOperation>,
        principals: Vec<String>,
        identity_override: Option<(u32, u32, String)>,
    ) -> PathBuf {
        let identity = current_peer_identity();
        let (uid, gid, executable_sha256) =
            identity_override.unwrap_or((identity.uid, identity.gid, identity.executable_sha256));
        let policy = PeerPolicy {
            version: 1,
            bindings: vec![PeerBinding {
                id: "test-client".into(),
                uid,
                gid,
                executable_sha256,
                operations,
                principals,
            }],
        };
        let path = dir.join("peer-policy.json");
        fs::write(
            &path,
            serde_json::to_vec(&policy).expect("peer policy json"),
        )
        .expect("peer policy");
        let signature = sign_from_files(key_path, "root/test", 1, ControlKind::PeerPolicy, &path)
            .expect("peer signature");
        fs::write(
            signature_sidecar_path(&path),
            serde_json::to_vec(&signature).expect("peer signature json"),
        )
        .expect("peer sidecar");
        path
    }

    fn config(dir: &Path, root_policy_path: PathBuf, peer_policy_path: PathBuf) -> ServiceConfig {
        ServiceConfig {
            socket_path: dir.join("trusted.sock"),
            root_policy_path,
            minimum_epoch_path: dir.join("minimum-epoch"),
            peer_policy_path,
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
        let (root_path, key_path) = write_root(&dir, 2, SignerStatus::Active);
        let peer_path =
            write_peer_policy(&dir, &key_path, vec![PeerOperation::Status], vec![], None);
        let service_config = config(&dir, root_path.clone(), peer_path);
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
    fn unix_service_authenticates_peer_and_persists_audit() {
        let dir = temp_dir("socket");
        let (root_path, key_path) = write_root(&dir, 4, SignerStatus::Active);
        let principal_path = write_signed_principal(&dir, &key_path);
        let peer_path = write_peer_policy(
            &dir,
            &key_path,
            vec![PeerOperation::Status, PeerOperation::Verify],
            vec!["developer-ai/test".into()],
            None,
        );
        let service_config = config(&dir, root_path.clone(), peer_path);
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
        assert!(ledger.records().iter().any(|record| {
            record.event.action == "ipc.peer.authenticated"
                && record.event.metadata.contains_key("peer_pid")
                && record.event.metadata.get("peer_pidfd_bound").map(String::as_str) == Some("true")
                && record.event.metadata.contains_key("peer_executable_sha256")
        }));
        assert!(
            ledger
                .records()
                .iter()
                .any(|record| record.event.action == "control.verify")
        );
    }

    #[test]
    fn unbound_peer_is_rejected_before_request_authorization() {
        let dir = temp_dir("peer-deny");
        let (root_path, key_path) = write_root(&dir, 5, SignerStatus::Active);
        let identity = current_peer_identity();
        let peer_path = write_peer_policy(
            &dir,
            &key_path,
            vec![PeerOperation::Status],
            vec![],
            Some((
                identity.uid.saturating_add(1),
                identity.gid,
                identity.executable_sha256,
            )),
        );
        let service_config = config(&dir, root_path, peer_path);
        let socket = service_config.socket_path.clone();
        let service = TrustedService::open(service_config).expect("service");
        let handle = std::thread::spawn(move || service.serve(Some(1)));
        wait_for_socket(&socket);

        let response = request(&socket, &ServiceRequest::Status).expect("response");
        assert!(matches!(
            response,
            ServiceResponse::Error { ref code, .. } if code == "peer_authentication_failed"
        ));
        handle.join().expect("thread").expect("serve");
    }

    #[test]
    fn peer_cannot_claim_unbound_principal() {
        let dir = temp_dir("principal-deny");
        let (root_path, key_path) = write_root(&dir, 6, SignerStatus::Active);
        let principal_path = write_signed_principal(&dir, &key_path);
        let peer_path = write_peer_policy(
            &dir,
            &key_path,
            vec![PeerOperation::Supervise],
            vec!["security-ai/test".into()],
            None,
        );
        let service_config = config(&dir, root_path, peer_path);
        let socket = service_config.socket_path.clone();
        let service = TrustedService::open(service_config).expect("service");
        let handle = std::thread::spawn(move || service.serve(Some(1)));
        wait_for_socket(&socket);

        let response = request(
            &socket,
            &ServiceRequest::Supervise {
                principal: principal_path,
                job: dir.join("not-needed.json"),
            },
        )
        .expect("response");
        assert!(matches!(
            response,
            ServiceResponse::Error { ref code, .. } if code == "peer_principal_denied"
        ));
        handle.join().expect("thread").expect("serve");
    }

    #[test]
    fn running_service_keeps_root_snapshot_until_controlled_restart() {
        let dir = temp_dir("root-snapshot");
        let (root_path, key_path) = write_root(&dir, 7, SignerStatus::Active);
        let principal_path = write_signed_principal(&dir, &key_path);
        let peer_path = write_peer_policy(
            &dir,
            &key_path,
            vec![PeerOperation::Verify],
            vec!["developer-ai/test".into()],
            None,
        );
        let service_config = config(&dir, root_path.clone(), peer_path);
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
                artifact: principal_path,
                kind: ControlKind::PrincipalPolicy,
            },
        )
        .expect("request");
        assert!(matches!(response, ServiceResponse::Verified { .. }));
        handle.join().expect("thread").expect("serve");

        assert!(matches!(
            TrustedService::open(service_config),
            Err(ServiceError::Control(ControlError::RevokedSigner { .. }))
        ));
    }
}
