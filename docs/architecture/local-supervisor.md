# Local Trusted Supervisor

## Scope

Phase 1 implements a Linux supervisor that launches untrusted AI/tool workers inside a deterministic security boundary.

The supervisor is Rust Trusted Core code. It contains no LLM SDK and does not make authorization decisions probabilistically.

## Authority model

The supervisor is the privileged mechanism. The worker is not.

A job has two external control inputs:
- principal policy;
- job specification.

Both must be outside the writable worker workspace. The supervisor hashes those inputs and records the hashes in the run audit metadata.

The worker receives:
- one writable /workspace;
- selected runtime paths mounted read-only;
- explicitly approved additional read-only host paths;
- isolated process/IPC/UTS state;
- an isolated network namespace when network mode is deny;
- a clean environment containing only the small runtime environment plus ORYVAEL identity metadata.

The normal host home directory is never mounted.

## Workspace provisioning

The trusted supervisor owns workspace provisioning. A task workspace must be created or adopted under supervisor-controlled ownership before an untrusted worker is launched.

This is not only lifecycle hygiene: user namespaces preserve ownership semantics. Reusing a directory owned by an unrelated host identity can make the mapped sandbox principal unable to write it, or create ambiguous trust over pre-existing content.

Repository/source material should therefore be copied or checked out into a supervisor-provisioned workspace, then exposed to the worker as /workspace.

## Linux backend

ORYVAEL composes two Linux mechanisms.

### Namespace envelope

util-linux unshare creates the outer user namespace and, for network-denied jobs, the network namespace.

This is deliberately separated from Bubblewrap. On some modern Ubuntu configurations, AppArmor allows privileged user-namespace creation while restricting unprivileged user namespaces. The supervisor therefore detects rootless availability instead of weakening host security policy.

### Filesystem/process sandbox

Bubblewrap creates the mount/process containment layer.

The sandbox root is remounted read-only. After that operation, only the task workspace is bind-mounted writable at /workspace.

System runtime files such as /usr, /bin, /lib and the dynamic-loader configuration are mounted read-only.

HOME is /workspace/.oryvael/runtime/home.

TMPDIR is /workspace/.oryvael/runtime/tmp and /tmp resolves into that workspace-owned runtime directory.

This gives the worker no persistent writable host path outside its workspace.

## Network

NetworkMode::Deny is the default.

For a denied-network job, the supervisor creates a separate network namespace before the worker starts. No host network namespace is inherited.

NetworkMode::Host requires an explicit policy decision for:

    resource: network
    action: connect
    target: "*"

A job request cannot grant this capability to itself. Explicit deny still has precedence.

## Rootless versus trusted-service execution

ORYVAEL probes whether the host allows the required unprivileged user/network namespace operation.

If the probe succeeds, the same supervisor can run rootless.

If the probe fails, ORYVAEL does not silently execute unsandboxed. The intended OS deployment model is a small trusted supervisor service with the privilege required to construct namespaces on behalf of untrusted workers.

The reference CI tests both facts:
- the rootless probe can report unavailable;
- the trusted privileged path must still pass the complete confinement test.

## Resource limits

Wall-clock timeout is always supervised externally.

When a job declares:
- memory_bytes;
- cpu_seconds;
- file_size_bytes;

the supervisor wraps namespace creation with Linux prlimit.

A requested resource control is not silently discarded. Failure to start a required enforcement primitive fails the job.

## Capability checks

Before the sandbox starts, the supervisor evaluates:
- workspace.mount_rw for /workspace;
- process.execute for the requested entry executable;
- network.connect when host networking is requested;
- host_path.read for every additional host path.

Policy is explicit-deny-first and default-deny.

## Audit

Each run receives one operation_id.

The JSONL journal records:
- run request;
- every policy evaluation;
- sandbox start or launch failure;
- sandbox exit;
- result status;
- stdout/stderr artifact hashes.

Before appending, the supervisor reloads and verifies the complete existing hash chain. Corruption is fail-closed.

The journal is outside /workspace and is never mounted into the worker.

The current Phase 1 journal is a single-writer local primitive. A long-running centralized audit service remains a hardening task, not a missing confinement control for the local supervisor.

## Artifact store

stdout and stderr are copied after execution into a SHA-256 content-addressed store outside the workspace.

The returned JobResult contains:
- operation_id;
- success/timed_out;
- exit code;
- stdout artifact hash/path;
- stderr artifact hash/path;
- audit path.

## CI assurance

The sandbox-smoke job executes the real Linux sandbox and verifies:
1. the worker can write its task workspace;
2. writing to the sandbox root outside /workspace is rejected;
3. a network-denied worker cannot establish the test network connection;
4. no escape marker appears on the host;
5. the resulting audit chain verifies;
6. all privileged audit events carry an operation_id;
7. a principal with explicit network deny cannot self-grant host networking through its job specification;
8. a job control file inside the writable worker workspace is rejected.

These are implementation tests, not a claim of complete sandbox security.

## Current limitations

Phase 1 authorizes the entry executable but does not yet broker every child exec separately. Child processes remain inside the same filesystem/network sandbox, but tool-level authorization will move into the Phase 2 Tool Broker.

The current reference also does not yet provide:
- seccomp profiles generated per tool;
- Landlock defense in depth;
- a persistent supervisor daemon protocol;
- remote/anchored audit checkpoints;
- cgroup-v2 resource accounting across a fleet.

Those are explicit follow-on hardening items.
