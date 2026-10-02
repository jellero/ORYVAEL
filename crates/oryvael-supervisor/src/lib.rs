#![forbid(unsafe_code)]

use oryvael_audit::{AuditError, AuditLedger, AuditRecord};
use oryvael_policy::evaluate;
use oryvael_protocol::{AuditDecision, AuditEvent, Operation, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

static OP_COUNTER: AtomicU64 = AtomicU64::new(1);

const SANDBOX_WORKSPACE: &str = "/workspace";
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    #[default]
    Deny,
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceLimits {
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    #[serde(default)]
    pub file_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobSpec {
    pub principal: String,
    pub change_id: String,
    pub workspace: PathBuf,
    pub command: Vec<String>,
    #[serde(default)]
    pub network: NetworkMode,
    #[serde(default)]
    pub read_only_paths: Vec<PathBuf>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub limits: ResourceLimits,
    pub audit_log: PathBuf,
    pub artifact_store: PathBuf,
}

fn default_timeout_seconds() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRef {
    pub sha256: String,
    pub bytes: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobResult {
    pub operation_id: String,
    pub success: bool,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub stdout: ArtifactRef,
    pub stderr: ArtifactRef,
    pub audit_log: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCommand {
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("ORYVAEL supervisor currently supports Linux only")]
    UnsupportedPlatform,
    #[error("invalid job specification: {0}")]
    InvalidSpec(String),
    #[error("principal mismatch: policy is {policy}, job requests {job}")]
    PrincipalMismatch { policy: String, job: String },
    #[error("control file must be outside the writable workspace: {0}")]
    ControlFileInsideWorkspace(PathBuf),
    #[error("audit log must be outside the writable workspace: {0}")]
    AuditInsideWorkspace(PathBuf),
    #[error("artifact store must be outside the writable workspace: {0}")]
    ArtifactStoreInsideWorkspace(PathBuf),
    #[error("read-only host path overlaps writable workspace: {0}")]
    ReadOnlyPathOverlapsWorkspace(PathBuf),
    #[error("policy denied {resource}.{action} on {target}: {reason}")]
    PolicyDenied {
        resource: String,
        action: String,
        target: String,
        reason: String,
    },
    #[error("sandbox launch failed: {0}")]
    SandboxLaunch(String),
    #[error("audit error: {0}")]
    Audit(#[from] AuditError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct PreparedJob {
    workspace: PathBuf,
    audit_log: PathBuf,
    artifact_store: PathBuf,
    read_only_paths: Vec<(PathBuf, PathBuf)>,
    runtime_dir: PathBuf,
}

struct AuditJournal {
    path: PathBuf,
    ledger: AuditLedger,
    file: File,
}

impl AuditJournal {
    fn open(path: &Path) -> Result<Self, SupervisorError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let ledger = if path.exists() {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let mut records = Vec::new();

            for (index, line) in reader.lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let record: AuditRecord = serde_json::from_str(&line).map_err(|error| {
                    SupervisorError::InvalidSpec(format!(
                        "invalid audit JSON at line {}: {error}",
                        index + 1
                    ))
                })?;
                records.push(record);
            }

            let ledger = AuditLedger::from_records(records);
            ledger.verify()?;
            ledger
        } else {
            AuditLedger::new()
        };

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            ledger,
            file,
        })
    }

    fn append(&mut self, event: AuditEvent) -> Result<AuditRecord, SupervisorError> {
        let record = self.ledger.append(event)?.clone();
        serde_json::to_writer(&mut self.file, &record)?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        Ok(record)
    }
}

struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    fn new(root: PathBuf) -> Result<Self, SupervisorError> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn put_file(&self, source: &Path) -> Result<ArtifactRef, SupervisorError> {
        let mut input = File::open(source)?;
        let temp_name = format!(".tmp-{}", new_operation_id());
        let temp_path = self.root.join(temp_name);
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;

        let mut hasher = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];

        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
            bytes += read as u64;
        }

        output.sync_all()?;
        let sha256 = hex::encode(hasher.finalize());
        let prefix = &sha256[..2];
        let target_dir = self.root.join("sha256").join(prefix);
        fs::create_dir_all(&target_dir)?;
        let target = target_dir.join(&sha256);

        if target.exists() {
            fs::remove_file(&temp_path)?;
        } else {
            fs::rename(&temp_path, &target)?;
        }

        Ok(ArtifactRef {
            sha256,
            bytes,
            path: target,
        })
    }
}

pub fn run_from_files(
    principal_path: impl AsRef<Path>,
    job_path: impl AsRef<Path>,
) -> Result<JobResult, SupervisorError> {
    if !cfg!(target_os = "linux") {
        return Err(SupervisorError::UnsupportedPlatform);
    }

    let job_path = canonical_existing_file(job_path.as_ref())?;
    let job_content = fs::read_to_string(&job_path)?;
    let spec: JobSpec = serde_json::from_str(&job_content)?;
    let workspace = prepare_workspace(&spec.workspace)?;

    let principal_path = canonical_existing_file(principal_path.as_ref())?;
    if principal_path.starts_with(&workspace) {
        return Err(SupervisorError::ControlFileInsideWorkspace(principal_path));
    }
    if job_path.starts_with(&workspace) {
        return Err(SupervisorError::ControlFileInsideWorkspace(job_path));
    }

    let principal_content = fs::read_to_string(&principal_path)?;
    let principal: Principal = serde_json::from_str(&principal_content)?;

    let principal_hash = sha256_hex(principal_content.as_bytes());
    let job_hash = sha256_hex(job_content.as_bytes());

    run_job_with_context(principal, spec, Some(principal_hash), Some(job_hash))
}

pub fn run_job(principal: Principal, spec: JobSpec) -> Result<JobResult, SupervisorError> {
    run_job_with_context(principal, spec, None, None)
}

fn run_job_with_context(
    principal: Principal,
    spec: JobSpec,
    principal_hash: Option<String>,
    job_hash: Option<String>,
) -> Result<JobResult, SupervisorError> {
    if !cfg!(target_os = "linux") {
        return Err(SupervisorError::UnsupportedPlatform);
    }
    if spec.principal != principal.principal {
        return Err(SupervisorError::PrincipalMismatch {
            policy: principal.principal,
            job: spec.principal,
        });
    }
    if spec.command.is_empty() || spec.command[0].trim().is_empty() {
        return Err(SupervisorError::InvalidSpec(
            "command must contain a non-empty executable".into(),
        ));
    }
    if spec.change_id.trim().is_empty() {
        return Err(SupervisorError::InvalidSpec(
            "change_id must not be empty".into(),
        ));
    }
    if spec.timeout_seconds == 0 {
        return Err(SupervisorError::InvalidSpec(
            "timeout_seconds must be greater than zero".into(),
        ));
    }

    let prepared = prepare_job(&spec)?;
    let mut audit = AuditJournal::open(&prepared.audit_log)?;
    let operation_id = new_operation_id();

    let mut start_metadata = BTreeMap::new();
    start_metadata.insert("network".into(), format!("{:?}", spec.network).to_lowercase());
    start_metadata.insert("command".into(), spec.command[0].clone());
    if let Some(hash) = principal_hash {
        start_metadata.insert("principal_policy_sha256".into(), hash);
    }
    if let Some(hash) = job_hash {
        start_metadata.insert("job_spec_sha256".into(), hash);
    }

    audit.append(AuditEvent {
        timestamp_ns: now_ns(),
        actor: principal.principal.clone(),
        action: "supervisor.run.request".into(),
        target: SANDBOX_WORKSPACE.into(),
        decision: AuditDecision::Observed,
        change_id: Some(spec.change_id.clone()),
        operation_id: Some(operation_id.clone()),
        metadata: start_metadata,
    })?;

    authorize(
        &mut audit,
        &principal,
        &spec.change_id,
        &operation_id,
        Operation {
            resource: "workspace".into(),
            action: "mount_rw".into(),
            target: Some(SANDBOX_WORKSPACE.into()),
        },
    )?;

    authorize(
        &mut audit,
        &principal,
        &spec.change_id,
        &operation_id,
        Operation {
            resource: "process".into(),
            action: "execute".into(),
            target: Some(spec.command[0].clone()),
        },
    )?;

    if spec.network == NetworkMode::Host {
        authorize(
            &mut audit,
            &principal,
            &spec.change_id,
            &operation_id,
            Operation {
                resource: "network".into(),
                action: "connect".into(),
                target: Some("*".into()),
            },
        )?;
    }

    for (source, _) in &prepared.read_only_paths {
        authorize(
            &mut audit,
            &principal,
            &spec.change_id,
            &operation_id,
            Operation {
                resource: "host_path".into(),
                action: "read".into(),
                target: Some(source.to_string_lossy().into_owned()),
            },
        )?;
    }

    let stdout_path = prepared.runtime_dir.join(format!("{operation_id}.stdout"));
    let stderr_path = prepared.runtime_dir.join(format!("{operation_id}.stderr"));
    let stdout = File::create(&stdout_path)?;
    let stderr = File::create(&stderr_path)?;

    let sandbox = build_sandbox_command(&principal, &spec, &prepared, &operation_id)?;

    let mut command = Command::new(&sandbox.program);
    command
        .args(&sandbox.args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let mut metadata = BTreeMap::new();
            metadata.insert("error".into(), error.to_string());
            let _ = audit.append(AuditEvent {
                timestamp_ns: now_ns(),
                actor: principal.principal.clone(),
                action: "supervisor.sandbox.start".into(),
                target: spec.command[0].clone(),
                decision: AuditDecision::Failed,
                change_id: Some(spec.change_id.clone()),
                operation_id: Some(operation_id.clone()),
                metadata,
            });
            return Err(SupervisorError::SandboxLaunch(error.to_string()));
        }
    };

    audit.append(AuditEvent {
        timestamp_ns: now_ns(),
        actor: principal.principal.clone(),
        action: "supervisor.sandbox.start".into(),
        target: spec.command[0].clone(),
        decision: AuditDecision::Allowed,
        change_id: Some(spec.change_id.clone()),
        operation_id: Some(operation_id.clone()),
        metadata: BTreeMap::new(),
    })?;

    let deadline = Instant::now() + Duration::from_secs(spec.timeout_seconds);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }

        if Instant::now() >= deadline {
            child.kill()?;
            let status = child.wait()?;
            break (status, true);
        }

        thread::sleep(Duration::from_millis(50));
    };

    let store = ArtifactStore::new(prepared.artifact_store.clone())?;
    let stdout_ref = store.put_file(&stdout_path)?;
    let stderr_ref = store.put_file(&stderr_path)?;
    let success = status.success() && !timed_out;

    let mut finish_metadata = BTreeMap::new();
    finish_metadata.insert(
        "exit_code".into(),
        status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".into()),
    );
    finish_metadata.insert("timed_out".into(), timed_out.to_string());
    finish_metadata.insert("stdout_sha256".into(), stdout_ref.sha256.clone());
    finish_metadata.insert("stderr_sha256".into(), stderr_ref.sha256.clone());

    audit.append(AuditEvent {
        timestamp_ns: now_ns(),
        actor: principal.principal,
        action: "supervisor.sandbox.exit".into(),
        target: spec.command[0].clone(),
        decision: if success {
            AuditDecision::Observed
        } else {
            AuditDecision::Failed
        },
        change_id: Some(spec.change_id),
        operation_id: Some(operation_id.clone()),
        metadata: finish_metadata,
    })?;

    Ok(JobResult {
        operation_id,
        success,
        timed_out,
        exit_code: status.code(),
        stdout: stdout_ref,
        stderr: stderr_ref,
        audit_log: audit.path,
    })
}

fn authorize(
    audit: &mut AuditJournal,
    principal: &Principal,
    change_id: &str,
    operation_id: &str,
    operation: Operation,
) -> Result<(), SupervisorError> {
    let decision = evaluate(principal, &operation);
    let target = operation.target.clone().unwrap_or_default();

    let mut metadata = BTreeMap::new();
    metadata.insert("resource".into(), operation.resource.clone());
    metadata.insert("action".into(), operation.action.clone());
    metadata.insert("reason".into(), decision.reason.clone());
    if let Some(index) = decision.matched_grant {
        metadata.insert("matched_grant".into(), index.to_string());
    }

    audit.append(AuditEvent {
        timestamp_ns: now_ns(),
        actor: principal.principal.clone(),
        action: "policy.evaluate".into(),
        target: target.clone(),
        decision: if decision.allowed {
            AuditDecision::Allowed
        } else {
            AuditDecision::Denied
        },
        change_id: Some(change_id.into()),
        operation_id: Some(operation_id.into()),
        metadata,
    })?;

    if decision.allowed {
        Ok(())
    } else {
        Err(SupervisorError::PolicyDenied {
            resource: operation.resource,
            action: operation.action,
            target,
            reason: decision.reason,
        })
    }
}

fn prepare_job(spec: &JobSpec) -> Result<PreparedJob, SupervisorError> {
    let workspace = prepare_workspace(&spec.workspace)?;
    let runtime_dir = workspace.join(".oryvael").join("runtime");
    fs::create_dir_all(runtime_dir.join("home"))?;
    fs::create_dir_all(runtime_dir.join("tmp"))?;

    let audit_log = external_file_path(&spec.audit_log)?;
    if audit_log.starts_with(&workspace) {
        return Err(SupervisorError::AuditInsideWorkspace(audit_log));
    }

    let artifact_store = absolute_path(&spec.artifact_store)?;
    fs::create_dir_all(&artifact_store)?;
    let artifact_store = fs::canonicalize(&artifact_store)?;
    if artifact_store.starts_with(&workspace) {
        return Err(SupervisorError::ArtifactStoreInsideWorkspace(
            artifact_store,
        ));
    }

    let mut read_only_paths = Vec::new();
    for requested in &spec.read_only_paths {
        let destination = absolute_path(requested)?;
        let source = fs::canonicalize(&destination)?;
        if source.starts_with(&workspace) || destination.starts_with(&workspace) {
            return Err(SupervisorError::ReadOnlyPathOverlapsWorkspace(
                destination,
            ));
        }
        read_only_paths.push((source, destination));
    }

    Ok(PreparedJob {
        workspace,
        audit_log,
        artifact_store,
        read_only_paths,
        runtime_dir,
    })
}

pub fn build_sandbox_command(
    principal: &Principal,
    spec: &JobSpec,
    prepared: &PreparedJob,
    operation_id: &str,
) -> Result<SandboxCommand, SupervisorError> {
    let mut bwrap = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup-try".into(),
    ];

    if spec.network == NetworkMode::Deny {
        bwrap.push("--unshare-net".into());
    }

    bwrap.extend([
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--dir".into(),
        "/run".into(),
        "--dir".into(),
        "/etc".into(),
        "--clearenv".into(),
        "--setenv".into(),
        "PATH".into(),
        SAFE_PATH.into(),
        "--setenv".into(),
        "HOME".into(),
        "/workspace/.oryvael/runtime/home".into(),
        "--setenv".into(),
        "TMPDIR".into(),
        "/workspace/.oryvael/runtime/tmp".into(),
        "--setenv".into(),
        "ORYVAEL_PRINCIPAL_ID".into(),
        principal.principal.clone().into(),
        "--setenv".into(),
        "ORYVAEL_CHANGE_ID".into(),
        spec.change_id.clone().into(),
        "--setenv".into(),
        "ORYVAEL_OPERATION_ID".into(),
        operation_id.into(),
    ]);

    for path in system_runtime_paths(spec.network) {
        if let Some((source, destination)) = resolved_mount(&path)? {
            push_ro_bind(&mut bwrap, &source, &destination);
        }
    }

    for (source, destination) in &prepared.read_only_paths {
        push_ro_bind(&mut bwrap, source, destination);
    }

    bwrap.extend([
        "--bind".into(),
        prepared.workspace.clone().into_os_string(),
        SANDBOX_WORKSPACE.into(),
        "--symlink".into(),
        "workspace/.oryvael/runtime/tmp".into(),
        "/tmp".into(),
        "--chdir".into(),
        SANDBOX_WORKSPACE.into(),
        "--".into(),
    ]);

    for part in &spec.command {
        bwrap.push(part.into());
    }

    if has_limits(&spec.limits) {
        let mut args = Vec::new();

        if let Some(memory) = spec.limits.memory_bytes {
            args.push(format!("--as={memory}").into());
        }
        if let Some(cpu) = spec.limits.cpu_seconds {
            args.push(format!("--cpu={cpu}").into());
        }
        if let Some(file_size) = spec.limits.file_size_bytes {
            args.push(format!("--fsize={file_size}").into());
        }

        args.push("--".into());
        args.push("bwrap".into());
        args.extend(bwrap);

        Ok(SandboxCommand {
            program: "prlimit".into(),
            args,
        })
    } else {
        Ok(SandboxCommand {
            program: "bwrap".into(),
            args: bwrap,
        })
    }
}

fn has_limits(limits: &ResourceLimits) -> bool {
    limits.memory_bytes.is_some() || limits.cpu_seconds.is_some() || limits.file_size_bytes.is_some()
}

fn system_runtime_paths(network: NetworkMode) -> Vec<PathBuf> {
    let mut paths = vec![
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect::<Vec<_>>();

    if network == NetworkMode::Host {
        paths.extend(
            [
                "/etc/resolv.conf",
                "/etc/hosts",
                "/etc/nsswitch.conf",
                "/etc/ssl",
                "/etc/pki",
                "/etc/ca-certificates",
            ]
            .into_iter()
            .map(PathBuf::from),
        );
    }

    paths
}

fn resolved_mount(path: &Path) -> Result<Option<(PathBuf, PathBuf)>, SupervisorError> {
    if !path.exists() {
        return Ok(None);
    }
    let source = fs::canonicalize(path)?;
    Ok(Some((source, path.to_path_buf())))
}

fn push_ro_bind(args: &mut Vec<OsString>, source: &Path, destination: &Path) {
    args.push("--ro-bind".into());
    args.push(source.as_os_str().to_owned());
    args.push(destination.as_os_str().to_owned());
}

fn prepare_workspace(path: &Path) -> Result<PathBuf, SupervisorError> {
    let absolute = absolute_path(path)?;
    fs::create_dir_all(&absolute)?;
    let canonical = fs::canonicalize(&absolute)?;
    if !canonical.is_dir() {
        return Err(SupervisorError::InvalidSpec(format!(
            "workspace is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn canonical_existing_file(path: &Path) -> Result<PathBuf, SupervisorError> {
    let canonical = fs::canonicalize(absolute_path(path)?)?;
    if !canonical.is_file() {
        return Err(SupervisorError::InvalidSpec(format!(
            "control path is not a file: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn external_file_path(path: &Path) -> Result<PathBuf, SupervisorError> {
    let absolute = absolute_path(path)?;
    let file_name = absolute.file_name().ok_or_else(|| {
        SupervisorError::InvalidSpec(format!("path has no file name: {}", absolute.display()))
    })?;
    let parent = absolute.parent().ok_or_else(|| {
        SupervisorError::InvalidSpec(format!("path has no parent: {}", absolute.display()))
    })?;
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    Ok(parent.join(file_name))
}

fn absolute_path(path: &Path) -> Result<PathBuf, SupervisorError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn new_operation_id() -> String {
    let counter = OP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("op-{:x}-{:x}-{:x}", now_ns(), std::process::id(), counter)
}

fn now_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryvael_protocol::{CapabilityGrant, Effect, PrincipalKind};

    fn principal() -> Principal {
        Principal {
            principal: "developer-ai/test".into(),
            kind: PrincipalKind::AiAgent,
            grants: vec![
                CapabilityGrant {
                    effect: Effect::Allow,
                    resource: "workspace".into(),
                    actions: vec!["mount_rw".into()],
                    scope: Some("/workspace".into()),
                    expires_at: None,
                    delegable: false,
                },
                CapabilityGrant {
                    effect: Effect::Allow,
                    resource: "process".into(),
                    actions: vec!["execute".into()],
                    scope: Some("/usr/bin/python3".into()),
                    expires_at: None,
                    delegable: false,
                },
                CapabilityGrant {
                    effect: Effect::Deny,
                    resource: "network".into(),
                    actions: vec!["*".into()],
                    scope: None,
                    expires_at: None,
                    delegable: false,
                },
            ],
        }
    }

    fn spec(workspace: PathBuf) -> JobSpec {
        JobSpec {
            principal: "developer-ai/test".into(),
            change_id: "CHG-TEST".into(),
            workspace,
            command: vec!["/usr/bin/python3".into(), "-V".into()],
            network: NetworkMode::Deny,
            read_only_paths: vec![],
            timeout_seconds: 10,
            limits: ResourceLimits::default(),
            audit_log: PathBuf::from("/tmp/oryvael-test-audit.jsonl"),
            artifact_store: PathBuf::from("/tmp/oryvael-test-artifacts"),
        }
    }

    fn prepared(workspace: PathBuf) -> PreparedJob {
        PreparedJob {
            runtime_dir: workspace.join(".oryvael/runtime"),
            workspace,
            audit_log: PathBuf::from("/tmp/audit"),
            artifact_store: PathBuf::from("/tmp/artifacts"),
            read_only_paths: vec![],
        }
    }

    #[test]
    fn network_is_unshared_by_default() {
        let workspace = PathBuf::from("/tmp/oryvael-workspace");
        let spec = spec(workspace.clone());
        let command =
            build_sandbox_command(&principal(), &spec, &prepared(workspace), "op-test").unwrap();

        let args = command
            .args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(args.iter().any(|arg| arg == "--unshare-net"));
    }

    #[test]
    fn host_network_does_not_unshare_network_namespace() {
        let workspace = PathBuf::from("/tmp/oryvael-workspace");
        let mut spec = spec(workspace.clone());
        spec.network = NetworkMode::Host;

        let command =
            build_sandbox_command(&principal(), &spec, &prepared(workspace), "op-test").unwrap();

        let args = command
            .args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(!args.iter().any(|arg| arg == "--unshare-net"));
    }

    #[test]
    fn resource_limits_select_prlimit_wrapper() {
        let workspace = PathBuf::from("/tmp/oryvael-workspace");
        let mut spec = spec(workspace.clone());
        spec.limits.memory_bytes = Some(512 * 1024 * 1024);

        let command =
            build_sandbox_command(&principal(), &spec, &prepared(workspace), "op-test").unwrap();

        assert_eq!(command.program, OsString::from("prlimit"));
        assert!(command
            .args
            .iter()
            .any(|arg| arg.to_string_lossy().starts_with("--as=")));
    }
}
