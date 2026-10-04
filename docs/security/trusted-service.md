# Persistent Trusted Supervisor / Audit Service

## Purpose

`oryvael-service` is the persistent trusted process for the current Linux reference implementation. It owns the accepted root-policy snapshot, monotonic root epoch, signed local peer authorization, control-verification telemetry and supervisor lifecycle attribution outside short-lived CLI processes.

The service is part of the `oryvael-supervisor` Trusted Core package. Reaching its socket does not itself grant a caller AI-principal or administrator authority.

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

Both root policy and peer policy are deliberately fixed for one service instance. Changing either pathname on disk does not silently alter the authority of the running process. Governance changes cross a controlled service restart boundary.

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

## Kernel-authenticated and pidfd-bound IPC identity

The reference transport is a local Unix domain socket. On Linux, every accepted connection is authenticated before its request is deserialized.

The service obtains two independent kernel objects from the connected socket:

- `SO_PEERCRED` for PID, UID and GID;
- `SO_PEERPIDFD` for a pidfd referring to the peer process associated with the connection.

`SO_PEERPIDFD` is mandatory for the trusted-service path. A host kernel that cannot provide it is rejected rather than silently falling back to PID-only authentication.

The pidfd remains owned by the service for the full request lifecycle. The service polls it to verify that the peer has not exited while identity is being evaluated.

Executable identity is resolved as follows:

1. obtain `SO_PEERCRED` and `SO_PEERPIDFD` from the accepted socket;
2. require the pidfd to still identify a live process;
3. open `/proc/<pid>/exe` while that pidfd is live;
4. immediately re-check pidfd liveness;
5. use the opened executable file descriptor through `/proc/self/fd/<fd>` as the stable object used for pathname attribution and SHA-256 hashing;
6. re-check pidfd liveness after hashing;
7. require the signed peer binding to match `UID + GID + executable SHA-256`.

Opening the executable before hashing means the content decision is attached to the file object already acquired by the Trusted Core rather than repeatedly following a mutable `/proc/<pid>/exe` pathname.

After the authenticated peer sends its bounded request, and before the service authorizes or dispatches that request, the service checks pidfd liveness again and re-hashes the peer's current executable. A changed executable causes a fail-closed `peer_identity_changed` response and an `ipc.peer.identity_changed` audit event.

This materially closes the numeric-PID reuse/lifecycle race around `/proc/<pid>/exe` acquisition and detects an executable transition that persists through request dispatch.

PID remains audit attribution rather than static authorization state. The persistent authority tuple remains:

    UID + GID + executable SHA-256

with the process lifecycle additionally pinned by the kernel pidfd.

The implementation keeps the unsafe boundary narrow. `service.rs` remains `#![forbid(unsafe_code)]`. A private Linux-only `peercred` module contains only the native boundary needed for `getsockopt(SO_PEERCRED)`, `getsockopt(SO_PEERPIDFD)` and non-blocking pidfd `poll()`. No general-purpose networking or native-runtime dependency was added to the Trusted Core.

## Signed peer policy

`peer_policy` is a root-authorized control artifact, not unsigned daemon configuration.

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

The authority chain is therefore:

    kernel socket credentials
        -> kernel peer pidfd
        -> executable identity
        -> signed peer binding
        -> signed ORYVAEL principal
        -> capability/policy enforcement

A signed principal file alone is insufficient to impersonate that principal over trusted-service IPC.

## Request processing order

For each connection the service performs:

1. obtain kernel peer credentials;
2. obtain the kernel peer pidfd;
3. verify peer-process liveness;
4. acquire and hash the executable through an opened file descriptor;
5. match the signed peer binding;
6. reject an unbound peer without deserializing its request;
7. deserialize only for an authenticated peer;
8. revalidate pidfd liveness and current executable identity;
9. authorize the requested service operation;
10. for `supervise`, verify and parse the signed principal policy;
11. bind that exact principal ID to the authenticated peer;
12. execute the existing supervisor policy/sandbox/resource path.

For a normal rejected client the service drains a size-bounded payload without parsing it before returning the structured deny response. This avoids Unix-stream reset behavior caused by closing a socket with unread data while preserving the invariant that unauthenticated request content is not interpreted before peer authentication.

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
- `peer_pidfd_bound=true`;
- peer executable SHA-256;
- principal-policy SHA-256;
- job SHA-256.

These values are copied into the supervisor audit context before `run_job` executes. The principal is parsed from the exact bytes already authenticated by the root verifier; the original principal pathname is not re-opened after verification.

## Audit ownership

The service journal is single-writer for service-level events. In addition to lifecycle and control-verification events, it records:

- peer credential/pidfd acquisition failures;
- authenticated peers;
- unbound peers;
- persistent executable-identity changes before dispatch;
- operation allow/deny decisions;
- principal-binding denials;
- peer PID/UID/GID/executable-hash and pidfd-binding attribution;
- supervisor start/completion/failure.

`JsonlAuditJournal::open` verifies the existing hash chain before the service accepts requests. A corrupt journal prevents normal startup rather than being silently replaced.

This is not yet a single global audit daemon for every ORYVAEL component. Existing tool/workspace/release journals remain component-specific. Migrating those producers to authenticated central append ownership plus external checkpoints is a separate hardening step.

## Determinism and concurrency

The reference daemon remains deliberately single-threaded. One service instance serializes request handling and journal writes, giving deterministic service-audit ordering and avoiding multi-writer races.

Parallel execution should be introduced only with durable request identity, cancellation semantics, job ownership and ordered/single-owner audit ingestion.

## Security properties currently tested

The Trusted Core and end-to-end workflow cover:

- `SO_PEERCRED` identifies the expected Unix peer;
- `SO_PEERPIDFD` returns a live kernel peer-process handle;
- root epoch persists across restarts and rollback is rejected;
- an authorized UID/GID/executable binding can use allowed operations;
- peer PID, pidfd-bound state and executable hash reach the persistent audit chain;
- a process absent from the signed peer policy is rejected;
- a same-UID foreign executable is rejected;
- an authenticated peer cannot claim a principal absent from its binding;
- the running service keeps its pinned root until controlled restart;
- root revocation is enforced on the next service instance.

The complete CI continues to exercise Linux sandboxing, capability denial, Git workspaces, Python/Rust tool brokers, independent verifier evidence, reproducible builds, C2 proof and signed C3 release authorization.

## Deliberate limitations / next hardening

The current reference does not claim that executable hashing is cryptographic remote attestation of the code that produced every byte on the socket. In particular, an already-authorized local process compromised after authorization remains inside that process's authority boundary, and stronger identity can later incorporate service-manager identity, LSM labels, cgroup identity, measured boot or key-backed challenge protocols.

Remaining hardening includes:

- systemd packaging/socket activation and hardened service-unit policy;
- migration of every component audit producer into one authenticated central append service;
- external audit checkpoints / remote transparency anchoring;
- TPM or secure-element backed epoch state;
- sealed `memfd` transport for trusted IPC payloads;
- concurrent job scheduling, cancellation and durable recovery;
- optional stronger process/workload attestation beyond executable hash identity.

The socket remains mode `0600` as defense in depth even though authorization no longer relies on pathname permissions alone.
