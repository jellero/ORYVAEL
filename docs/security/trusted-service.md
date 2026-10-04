# Persistent Trusted Supervisor / Audit Service

## Purpose

`oryvael-service` is the persistent trusted process for the current Linux reference implementation. It owns the accepted root-policy snapshot, monotonic root epoch, signed local peer authorization, control-verification telemetry and supervisor lifecycle attribution outside short-lived CLI processes.

The service is part of the `oryvael-supervisor` Trusted Core package. It does not grant an AI principal administrator authority merely because that principal can reach the socket.

## System-owned paths

Production-style defaults are:

    /run/oryvael/trusted.sock
    /etc/oryvael/root-policy.json
    /etc/oryvael/root-policy.min-epoch
    /etc/oryvael/peer-policy.json
    /var/lib/oryvael/audit/trusted-service.jsonl

The binary accepts explicit path overrides for development and CI, including `--peer-policy` for the signed local-peer policy.

## Startup sequence

The service starts fail-closed:

1. canonicalize and read the root policy;
2. validate root format and signer identities;
3. read the persistent minimum accepted root epoch;
4. reject startup if the supplied root epoch is older than the persistent minimum;
5. atomically advance the minimum epoch when the root has moved forward;
6. materialize the exact root-policy bytes into a private read-only pinned snapshot;
7. verify `peer-policy.json` as the signed `peer_policy` control-artifact kind against that pinned root;
8. parse and validate peer bindings from the exact authenticated peer-policy bytes;
9. open and verify the persistent service audit journal;
10. bind the local Unix socket with mode `0600`;
11. append `service.started` with root and peer-policy provenance.

Both the root policy and peer policy are deliberately fixed for one service instance. Changing either pathname on disk does not silently alter the authority of the running process. Governance changes cross a controlled service restart boundary.

## Root and peer-policy rotation

The operational sequence is:

    publish signed governance state
        -> controlled service restart
        -> validate root epoch
        -> pin root bytes
        -> verify signed peer policy
        -> accept IPC

There is no unauthenticated remote reload command.

If an older root policy is restored after a newer epoch has been accepted, startup fails with a root-epoch rollback error. If the peer policy is unsigned, modified, signed by a revoked key or signed by a key not authorized for `peer_policy`, startup also fails closed.

## Kernel-authenticated IPC identity

The reference transport is a local Unix domain socket. On Linux, every accepted connection is identified with `SO_PEERCRED` before the request is deserialized.

The kernel supplies:

- PID;
- UID;
- GID.

The service then resolves `/proc/<pid>/exe` and computes the SHA-256 of the executable image visible through that process handle. A signed peer binding must match the exact tuple:

    UID + GID + executable SHA-256

PID is intentionally not a static authorization field because it is ephemeral. It is captured for each connection and retained as audit attribution.

The implementation keeps the unsafe boundary minimal: `service.rs` remains `#![forbid(unsafe_code)]`. A private Linux-only `peercred` shim contains the small `getsockopt(SOL_SOCKET, SO_PEERCRED)` FFI required on the pinned Rust toolchain; the crate root explicitly allows unsafe code only for that module. No general-purpose native or networking dependency was added to the Trusted Core.

## Signed peer policy

`peer_policy` is a root-authorized control artifact, not an unsigned daemon configuration file.

Each binding declares:

- stable binding ID;
- UID;
- GID;
- executable SHA-256;
- allowed service operations;
- exact ORYVAEL principal IDs that may be used with `supervise`.

Operations are closed over:

- `status`;
- `verify`;
- `supervise`.

A process that reaches the socket but does not match a signed binding is rejected before request authorization. A bound process cannot call an operation absent from its binding. A process authorized for `supervise` still cannot claim an arbitrary signed principal policy: the verified `Principal.principal` must also be listed in that peer binding.

This produces two separate gates:

    kernel process identity
        -> signed peer binding
        -> signed ORYVAEL principal
        -> capability/policy enforcement

A signed principal file alone is therefore insufficient to impersonate that principal over trusted-service IPC.

## Request processing order

For each connection the service performs:

1. obtain kernel peer credentials;
2. resolve and hash the peer executable;
3. match the signed peer binding;
4. reject an unbound peer without deserializing its request;
5. deserialize only for an authenticated peer;
6. authorize the requested service operation;
7. for `supervise`, verify and parse the signed principal policy;
8. bind that exact principal ID to the authenticated peer;
9. execute the existing supervisor policy/sandbox/resource path.

For a normal rejected client the service drains a size-bounded payload without parsing it before returning the structured deny response. This avoids Unix-stream reset behavior caused by closing a socket with unread data while preserving the invariant that untrusted request content is not interpreted before peer authentication.

## Supported operations

The protocol supports one bounded JSON request per connection:

- `status` — return service instance, root/peer-policy provenance, audit state and PID;
- `verify` — verify a signed privileged control artifact against the process-owned root snapshot;
- `supervise` — verify the bound principal policy and execute an existing `JobSpec` through the Trusted Supervisor.

The CLI binary is:

    oryvael-service serve --peer-policy PATH ...
    oryvael-service status ...
    oryvael-service verify --kind KIND --artifact PATH ...
    oryvael-service supervise --principal PATH --job PATH ...

## Supervision attribution

For a supervised request the service attaches at least:

- service version and instance ID;
- root-policy SHA-256 and epoch;
- peer-policy SHA-256;
- peer binding ID;
- kernel peer UID/GID/PID;
- peer executable SHA-256;
- principal-policy SHA-256;
- job SHA-256.

These values are copied into the supervisor audit context before `run_job` executes. The principal is parsed from the exact bytes already authenticated by the root verifier; the original principal pathname is not re-opened after verification.

## Audit ownership

The service journal is single-writer for service-level events. In addition to lifecycle and control-verification events, it records:

- peer credential acquisition failures;
- authenticated peers;
- unbound peers;
- operation allow/deny decisions;
- principal-binding denials;
- peer PID/UID/GID/executable hash attribution;
- supervisor start/completion/failure.

`JsonlAuditJournal::open` verifies the existing hash chain before the service accepts requests. A corrupt journal prevents normal startup rather than being silently replaced.

This is not yet a single global audit daemon for every ORYVAEL component. Existing tool/workspace/release journals remain component-specific. Migrating those producers to an authenticated central append service and adding external checkpoints are separate hardening steps.

## Determinism and concurrency

The reference daemon remains deliberately single-threaded. One service instance serializes request handling and journal writes, giving deterministic service-audit ordering and avoiding multi-writer races.

Parallel execution should be introduced only with durable request identity, cancellation semantics, job ownership and ordered/single-owner audit ingestion.

## Security properties currently tested

The Trusted Core tests cover:

- `SO_PEERCRED` returns the process identity expected from a Unix peer;
- root epoch persists across restarts and rollback is rejected;
- an authorized UID/GID/executable binding can use allowed operations;
- peer PID and executable hash reach the persistent audit chain;
- a process absent from the signed peer policy is rejected;
- an authenticated peer cannot claim a principal absent from its binding;
- the running service keeps its pinned root until controlled restart;
- root revocation is enforced on the next service instance.

The complete CI continues to exercise Linux sandboxing, capability denial, Git workspaces, Python/Rust tool brokers, independent verifier evidence, reproducible builds, C2 proof and signed C3 release authorization.

## Deliberate limitations / next hardening

The current reference does not yet claim:

- pidfd-backed executable identity that remains stable across every possible `/proc/<pid>` lifecycle race;
- systemd packaging/socket activation and hardened service-unit policy;
- migration of every component audit producer into one central append service;
- external audit checkpoints / remote transparency anchoring;
- TPM or secure-element backed epoch state;
- sealed `memfd` transport for trusted IPC payloads;
- concurrent job scheduling, cancellation and durable recovery.

The socket remains mode `0600` as defense in depth even though authorization no longer relies on pathname permissions alone.
