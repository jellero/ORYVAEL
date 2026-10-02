# Local Trusted Supervisor

## Scope

Phase 1 introduces a Linux supervisor that launches untrusted workers inside a constrained sandbox.

The supervisor is deterministic Rust code. It contains no LLM SDK and does not decide policy probabilistically.

## Security boundary

A job has two control files:
- principal policy;
- job specification.

Both must be outside the writable worker workspace.

The worker receives only:
- a writable /workspace;
- selected system runtime paths mounted read-only;
- explicitly approved extra read-only host paths;
- /proc and a minimal /dev;
- a clean environment with ORYVAEL identity metadata.

The host home directory is not mounted.

## Linux backend

Reference enforcement uses Bubblewrap.

Default isolation:
- user namespace;
- PID namespace;
- IPC namespace;
- UTS namespace;
- cgroup namespace when available;
- independent network namespace;
- new terminal session;
- process dies with sandbox parent.

Network is denied by default.

If a job explicitly requests host network, the principal must hold the network.connect capability for *.

## Filesystem

The task workspace is the only normal writable host mount.

HOME is placed under /workspace/.oryvael/runtime/home.

TMPDIR is placed under /workspace/.oryvael/runtime/tmp, and /tmp is a symlink into that workspace subtree.

System runtime directories such as /usr, /bin and loader paths are mounted read-only. This is a baseline execution environment, not access to user data.

Additional host paths require an explicit host_path.read capability.

## Resource limits

When a job declares memory, CPU-time or per-file-size limits, the supervisor wraps Bubblewrap with Linux prlimit.

No requested resource limit silently degrades. If prlimit or Bubblewrap cannot start, the run fails.

Wall-clock timeout is independently enforced by the supervisor.

## Audit

Each run receives one operation ID.

The audit log records:
- run request;
- every policy evaluation;
- sandbox start;
- sandbox exit or failure;
- stdout/stderr artifact hashes.

The audit file is outside the workspace and the worker never receives it as a mount.

On startup the complete existing hash chain is verified. A corrupted audit log makes the supervisor fail closed.

The Phase 1 JSONL journal is single-writer by design. Multi-process centralized audit is deferred to the audit service milestone.

## Artifacts

stdout and stderr are copied after execution into a content-addressed SHA-256 store outside the workspace.

The worker cannot rewrite those stored artifacts after completion.

## Important limitation

Phase 1 authorizes the worker executable being launched, but does not yet provide a syscall-level allowlist for every child executable that the worker starts inside its sandbox.

This does not grant host filesystem or host network access: child processes remain inside the same namespace and mount boundary. A brokered per-tool execution model is planned for the AI Development Factory phase.

## Host prerequisites

Reference Linux host:
- bubblewrap (bwrap);
- prlimit from util-linux when resource limits are requested.

If unprivileged user namespaces are disabled, Bubblewrap may fail. ORYVAEL treats that as an unavailable mandatory control rather than falling back to unsandboxed execution.
