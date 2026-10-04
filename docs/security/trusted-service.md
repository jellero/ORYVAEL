# Persistent Trusted Supervisor / Audit Service

## Purpose

`oryvael-service` is the persistent trusted process for the current Linux reference implementation. It moves high-authority root ownership, monotonic root epoch persistence, control-verification telemetry and supervisor lifecycle attribution out of short-lived CLI processes.

The service is part of the `oryvael-supervisor` Trusted Core package. It does not add a new dependency layer and does not grant AI principals administrator authority.

## System-owned paths

Production-style defaults are:

    /run/oryvael/trusted.sock
    /etc/oryvael/root-policy.json
    /etc/oryvael/root-policy.min-epoch
    /var/lib/oryvael/audit/trusted-service.jsonl

The binary accepts explicit path overrides for development and CI.

## Startup sequence

The service starts fail-closed:

1. canonicalize and read the root policy;
2. validate the root policy format and signer identities;
3. read the persistent minimum accepted root epoch;
4. reject startup if the supplied root epoch is older than the persistent minimum;
5. atomically advance the minimum epoch when the root has moved forward;
6. materialize the exact root-policy bytes into a private read-only pinned snapshot;
7. open and verify the persistent service audit journal;
8. bind the local Unix socket with mode `0600`;
9. append `service.started` to the service journal.

The root policy is deliberately loaded once per service instance. Editing `/etc/oryvael/root-policy.json` does not silently change the authority of a process that is already running.

## Root rotation

Root rotation therefore has an explicit operational boundary:

    publish new root policy
        -> controlled service restart
        -> validate new policy
        -> persist monotonic epoch
        -> pin new root bytes
        -> accept requests

There is no unauthenticated remote reload command.

If an older root policy is restored after a newer epoch has been accepted, the next service start fails with a root-epoch rollback error.

## IPC

The reference transport is a local Unix domain socket. The current protocol supports one JSON request per connection and size-bounds both requests and responses.

Supported operations are:

- `status` — return service instance identity, root hash/epoch, persistent epoch, audit path/count/head and PID;
- `verify` — verify a signed privileged control artifact against the process-owned root snapshot;
- `supervise` — verify the principal policy and execute an existing `JobSpec` through the Trusted Supervisor.

The CLI binary is:

    oryvael-service serve ...
    oryvael-service status ...
    oryvael-service verify --kind KIND --artifact PATH ...
    oryvael-service supervise --principal PATH --job PATH ...

## Supervision path

For a supervised request the service:

1. verifies the principal policy against its pinned root;
2. parses the `Principal` from the exact authenticated bytes;
3. reads and hashes the job specification;
4. attaches service instance, root hash, root epoch, principal-policy hash and job hash to the supervisor audit context;
5. executes through `run_job`, preserving the existing policy/sandbox/resource/audit enforcement;
6. records service-level start/completion/failure telemetry in its own persistent journal.

The service does not re-open the principal policy after verification.

## Audit ownership

The service journal is single-writer for service-level events. It records:

- service start/stop;
- successful and denied root-control verification;
- supervisor request start;
- supervisor completion/failure;
- root policy identity and service instance attribution.

`JsonlAuditJournal::open` verifies the existing hash chain before the service accepts requests. A corrupt service journal therefore prevents normal startup rather than being silently replaced.

This is not yet a single global audit daemon for every ORYVAEL component. Existing supervisor/tool/workspace/release journals remain component-specific. Migrating those producers to an authenticated central append service and adding external checkpoints are separate hardening steps.

## Determinism and concurrency

The reference daemon is deliberately single-threaded. One service instance serializes request handling and service-journal writes, giving deterministic audit ordering and avoiding multi-writer journal races.

Parallel request execution should be introduced only together with explicit request identity, job ownership and an ordered/single-owner audit ingestion design.

## Security properties currently tested

The Trusted Core test suite verifies that:

- a root epoch persists across service restarts;
- advancing the epoch is durable;
- restoring an older root is rejected;
- the Unix service can answer status and signed-control verification requests;
- the resulting service audit chain remains valid;
- modifying the root-policy pathname while a service is running does not change that running instance's authority;
- after a controlled restart, a newly revoked signer is rejected.

The existing full CI also continues to exercise Linux sandboxing, capability denial, Git workspaces, Python/Rust tool brokers, independent verifier evidence, reproducible builds, C2 proof and signed C3 release authorization.

## Deliberate limitations / next hardening

The current reference does not yet claim:

- authenticated Unix peer identity (`SO_PEERCRED`) or principal-to-peer binding;
- systemd packaging/socket activation and hardened service-unit policy;
- migration of every component audit producer into one central append service;
- external audit checkpoints / remote transparency anchoring;
- TPM or secure-element backed epoch state;
- sealed `memfd` transport for all trusted IPC payloads;
- concurrent job scheduling, cancellation and durable job recovery.

Until peer authentication exists, the production Unix socket must remain restricted to a trusted local owner/group. The `0600` default intentionally fails toward the narrowest access model.
