# ORYVAEL Roadmap

## Phase 0 — Architecture foundation

Status: complete for the reference foundation.

Delivered:
- Constitution v0.1;
- trust model;
- machine-readable schemas;
- Architecture Compiler;
- Rust workspace;
- policy and audit primitives;
- CI gates.

Evidence gate:
- formatting, compilation, Clippy and tests pass;
- schemas parse;
- architecture/system.json is validated in CI.

## Phase 1 — Local Trusted Supervisor

Status: alpha implementation complete; hardening continues.

Delivered:
- principal identity and external policy input;
- Linux namespace/mount sandbox;
- read-only sandbox root with one writable task workspace;
- network deny by default;
- policy-gated host networking;
- policy-gated read-only host mounts;
- verified persistent audit chain;
- SHA-256 content-addressed stdout/stderr artifacts;
- wall-clock timeout;
- optional prlimit memory/CPU/file-size limits;
- supervisor host preflight;
- CLI supervise/doctor commands;
- persistent Unix-socket Trusted Supervisor/Audit Service;
- process-lifetime pinned root-policy ownership inside the service;
- atomic persistent monotonic root-policy epoch with restart rollback rejection;
- signed `peer_policy` as a root-authorized control artifact;
- Linux `SO_PEERCRED` acquisition before request deserialization;
- UID/GID plus executable-SHA-256 peer binding;
- per-binding service-operation allowlists;
- exact peer-to-ORYVAEL-principal binding for supervised execution;
- peer PID/UID/GID/executable attribution in the service and supervisor audit contexts;
- single-writer service journal for root verification, IPC authorization and supervisor lifecycle telemetry;
- explicit controlled-restart boundary for root-policy and peer-policy rotation;
- real Linux confinement smoke test in CI;
- negative tests for network self-grant, worker-writable controls, unbound IPC peers and principal spoofing.

Phase 1 exit criteria and current evidence:
- Developer AI writes only the task workspace: verified by real sandbox smoke test.
- Network deny is enforceable: verified by real socket attempt inside the sandbox.
- Every privileged operation has an audit ID: verified by audit assertions in CI.
- Agent cannot self-grant: verified by requesting host networking under an explicit network deny and requiring rejection.
- Root epoch survives trusted-service restart and rejects rollback: verified by Trusted Core tests.
- A running trusted service keeps a stable pinned root until controlled restart: verified by root-replacement test.
- An unbound local process cannot use trusted-service authority: verified by signed-peer-policy negative test.
- A bound process cannot claim an ORYVAEL principal absent from its binding: verified before job execution.

Hardening carried into Phase 1.x / Phase 2:
- pidfd-backed process/executable identity hardening beyond `/proc/<pid>/exe` hashing;
- migration of remaining component journals into a single-owner audit ingestion service plus external checkpoints;
- service manager packaging/hardening and durable job recovery;
- distribution/hardware compatibility matrix;
- seccomp/Landlock defense in depth;
- cgroup-v2 accounting and lifecycle cleanup.

## Phase 2 — AI Development Factory

Status: implementation in progress; the reference development-factory path is operational.

Delivered foundation:
- named tool/action catalog with no arbitrary command surface;
- Ed25519-signed tool catalogs verified fail-closed;
- common `oryvael-control` root verifier for tool catalogs, change plans, principal policies, workspace registries and signed peer policies;
- exact control-artifact SHA-256 binding inside detached signatures;
- versioned root signer identities with artifact-kind authorization;
- explicit active/revoked key state and rejection of cryptographically valid signatures from revoked key versions;
- monotonic root-policy epoch with anti-rollback minimum state;
- system root defaults at `/etc/oryvael/root-policy.json` and `/etc/oryvael/root-policy.min-epoch`;
- persistent Trusted Supervisor service owns and pins root-policy bytes for its process lifetime;
- persistent service advances root epoch atomically and rejects rollback across restart;
- root-authorized peer policy binds kernel process identity to trusted-service operations and ORYVAEL principals;
- service-level root verification, IPC authorization and lifecycle events are written by one trusted journal owner;
- ephemeral CI roots with no committed private root key;
- root-control enforcement at public file-based crate boundaries for supervisor, workspace, tool broker, build and proof;
- direct-crate anti-bypass integration tests requiring unsigned privileged controls to fail closed;
- verified-byte pinning for privileged control artifacts;
- nested proof-to-build control verification on pinned signed snapshots rather than mutable source pathnames;
- source-replacement test proving a verified token retains authenticated bytes after pathname mutation;
- immutable change-plan hash binding for brokered execution and verifier evidence;
- developer actions must be explicitly requested by the plan;
- Test/Security/Reviewer roles must differ from the producer;
- supervisor-enforced tool.execute capability;
- tool/catalog/invocation/principal hashes recorded in audit context;
- fixed argv, network policy, timeout and resource limits per catalog action;
- registry-controlled Git worktree/branch provisioning;
- Rust compiler and test profiles using an explicit read-only toolchain mount;
- deterministic Rust fuzz-smoke profile with an independently attributed Security AI verifier;
- protected verifier evidence derived from the tamper-evident audit chain;
- deterministic proof-package generator and eligibility engine;
- locked Cargo dependency graph capture and deterministic SBOM/build manifest;
- independent reproducible-build comparison with artifact mismatch veto;
- build/SBOM provenance bound into audited C2+ proof packages;
- deterministic release gate that rebuilds audited proof, hashes the actual artifact and enforces rollout ceilings;
- cryptographically signed, policy-authorized human approval verification for C3/C4 release decisions.

Next deliverables:
- harden local process identity with pidfd-backed lifecycle semantics;
- migrate remaining supervisor/workspace/tool/release audit producers to authenticated single-owner audit ingestion and external checkpoints;
- package and harden the persistent service under the system service manager, including clean restart/recovery behavior;
- add durable job registry, cancellation and crash recovery without weakening attribution;
- evaluate sealed `memfd`/kernel-handle backed control transport as defense in depth beyond the current private read-only snapshot model;
- evaluate TPM/secure-element backed monotonic epoch storage and root-key recovery procedures;
- evaluate threshold/multi-party authorization for root-policy and highly privileged catalog changes;
- replace the bounded fuzz-smoke profile with a coverage-guided fuzz backend while preserving broker isolation;
- complete concrete Architect and Reviewer workflows around the existing role enforcement;
- central metrics, logs and traces;
- end-to-end C1 generation demo starting from intent and finishing at a packaged artifact without host-admin authority.

Exit:
- a C1 ORYVAEL component is generated, independently verified and packaged end-to-end without the AI receiving host-admin authority;
- implementation and verification principals are independently attributable;
- all tool invocations are capability checked and audited.

## Phase 3 — Immutable Desktop Prototype

Deliver bootable image, A/B updates, recovery, Desktop shell, app runtime, development workspace and observability dashboards.

Exit:
- fault-injected rollback works;
- app capability UI works;
- staged test-fleet rollout works.

## Phase 4 — Desktop Alpha

Deliver hardware matrix, GPU/Wayland path, secrets/passkeys, signed apps and user governance console.

Exit:
- daily-driver pilot on defined hardware;
- independent Trusted Core security review;
- measurable recovery objectives.

## Phase 5 — ARM64 Mobile Prototype

Deliver Mobile shell, telephony/sensor/camera brokers, energy/background policy and secure-element integration.

Exit:
- common app/capability contracts work on Desktop and Mobile;
- continuity transfers state without silently transferring privilege.

## Phase 6 — Kernel Decision

Evaluate Linux versus a custom kernel using:
- TCB size;
- vulnerability exposure;
- driver burden;
- capability semantics;
- performance;
- energy;
- maintainability;
- formal-verification feasibility.

A custom kernel proceeds only if evidence justifies its cost.

## Long-term target

Routine implementation and maintenance may become predominantly AI-operated while C3/C4 authority, root keys, attribution and release evidence remain explicitly human governed.
