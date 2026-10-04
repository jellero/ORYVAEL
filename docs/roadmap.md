# ORYVAEL Roadmap

ADR-0005 supersedes the earlier Linux-first product-runtime direction. The roadmap therefore has two coordinated tracks:

- the host-side trusted-core/reference track, which validates governance, policy, audit, proof, release and AI-development-factory semantics;
- the native ORYVAEL OS track, which owns the product kernel, userland and hardware/runtime boundary.

Linux-hosted components remain valuable as reference implementations and migration sources, but they are not the ORYVAEL product runtime.

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

## Phase 1 — Local Trusted Supervisor reference

Status: alpha implementation complete; hardening continues on the host-side reference path.

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
- mandatory Linux `SO_PEERPIDFD` process-lifecycle binding for trusted-service IPC;
- pidfd liveness checks bracketing executable acquisition and hashing;
- opened executable-FD hashing rather than repeated mutable pathname traversal;
- executable revalidation after request receipt and before authorization/dispatch;
- UID/GID plus executable-SHA-256 peer binding;
- per-binding service-operation allowlists;
- exact peer-to-ORYVAEL-principal binding for supervised execution;
- peer PID/UID/GID/executable/pidfd-bound attribution in service and supervisor audit contexts;
- single-writer service journal for root verification, IPC authorization and supervisor lifecycle telemetry;
- explicit controlled-restart boundary for root-policy and peer-policy rotation;
- real Linux confinement smoke test in CI;
- end-to-end exact-binary trusted-service smoke test with same-UID foreign-executable rejection;
- negative tests for network self-grant, worker-writable controls, unbound IPC peers and principal spoofing.

Phase 1 exit criteria and current evidence:
- Developer AI writes only the task workspace: verified by real sandbox smoke test.
- Network deny is enforceable: verified by real socket attempt inside the sandbox.
- Every privileged operation has an audit ID: verified by audit assertions in CI.
- Agent cannot self-grant: verified by requesting host networking under an explicit network deny and requiring rejection.
- Root epoch survives trusted-service restart and rejects rollback: verified by Trusted Core tests.
- A running trusted service keeps a stable pinned root until controlled restart: verified by root-replacement test.
- An unbound local process cannot use trusted-service authority: verified by signed-peer-policy negative test.
- A same-UID process with a different executable cannot use the signed peer binding: verified end-to-end.
- A bound process cannot claim an ORYVAEL principal absent from its binding: verified before job execution.
- Trusted IPC identity is tied to a kernel pidfd and revalidated before dispatch.

Hardening carried into later reference work and native-service migration:
- migration of remaining component journals into a single-owner audit ingestion service plus external checkpoints;
- service manager packaging/hardening and durable job recovery;
- optional stronger workload identity/attestation beyond executable hashing;
- seccomp/Landlock and cgroup-v2 defense in depth on Linux-hosted reference infrastructure;
- native ORYVAEL equivalents at the system-service and kernel capability boundaries.

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
- pidfd-backed trusted IPC process lifecycle with no silent PID-only fallback;
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
- migrate remaining supervisor/workspace/tool/release audit producers to authenticated single-owner audit ingestion and external checkpoints;
- package and harden the persistent host-side reference service, including clean restart/recovery behavior;
- add durable job registry, cancellation and crash recovery without weakening attribution;
- evaluate sealed `memfd`/kernel-handle backed control transport as defense in depth beyond the current private read-only snapshot model;
- evaluate TPM/secure-element backed monotonic epoch storage and root-key recovery procedures;
- evaluate threshold/multi-party authorization for root-policy and highly privileged catalog changes;
- evaluate stronger workload identity using service-manager identity, LSM/cgroup labels, measured boot or key-backed challenge mechanisms;
- replace the bounded fuzz-smoke profile with a coverage-guided fuzz backend while preserving broker isolation;
- complete concrete Architect and Reviewer workflows around the existing role enforcement;
- central metrics, logs and traces;
- end-to-end C1 generation demo starting from intent and finishing at a packaged artifact without host-admin authority;
- define migration contracts for moving trusted-core semantics into native ORYVAEL services.

Exit:
- a C1 ORYVAEL component is generated, independently verified and packaged end-to-end without the AI receiving host-admin authority;
- implementation and verification principals are independently attributable;
- all tool invocations are capability checked and audited;
- control, proof and audit semantics are specified strongly enough to port into the native runtime without weakening invariants.

## Phase 3 — Native Kernel Foundation

Status: implementation in progress; the first x86_64 bare-metal userspace boundary is operational.

Delivered:
- x86_64 UEFI boot image;
- firmware memory-map capture and `ExitBootServices` handoff;
- physical 4 KiB frame allocator;
- kernel heap;
- ORYVAEL-owned CR3/PML4 root;
- fresh ring-3 code/data/stack page-table branch without widening inherited supervisor mappings;
- GDT and TSS kernel privilege-transition stack;
- 32 architectural exception gates with fail-closed dispatch;
- 100 Hz PIT/PIC timer interrupt path;
- DPL3 syscall gate;
- first `init` payload at CPL3;
- timer preemption observation while ring-3 code executes;
- capability-checked IPC mailbox roundtrip;
- minimal RAM filesystem and `/hello` read path;
- recovery kernel console;
- QEMU/OVMF CI that verifies the native userspace path and archives the boot image.

Next deliverables:
1. rebuild the complete kernel virtual address space with ORYVAEL-owned lower-level page tables instead of retaining inherited mappings;
2. add recoverable per-process exception/fault termination;
3. replace PIT/PIC bootstrap routing with local APIC and IOAPIC;
4. add kernel threads, saved contexts and context switching among multiple runnable ring-3 processes;
5. grow the fixed capability mailbox into a kernel object/handle table with rights transfer and blocking IPC;
6. add storage drivers and a persistent filesystem service;
7. add framebuffer/graphics input and networking drivers/services;
8. port governance, audit and root-control semantics from the host reference into native services;
9. add an ARM64 boot path after the x86_64 kernel contracts stabilize.

Exit:
- ORYVAEL boots without a host OS beneath it;
- kernel virtual-memory ownership no longer depends on inherited lower-level firmware mappings;
- multiple isolated ring-3 processes can be scheduled and terminated independently on faults;
- capability-bearing IPC is represented by kernel-managed objects/handles rather than fixed test constants;
- native CI continuously verifies the privilege boundary and core kernel invariants.

## Phase 4 — Immutable Desktop Prototype

Deliver persistent storage, A/B updates, recovery, Desktop shell, app runtime, development workspace, graphics/input/network services and observability dashboards on the native ORYVAEL runtime.

Exit:
- fault-injected rollback works;
- app capability UI works;
- staged test-fleet rollout works;
- routine desktop operation does not depend on a host operating system beneath ORYVAEL.

## Phase 5 — Desktop Alpha

Deliver defined hardware matrix, GPU/display path, secrets/passkeys, signed apps, user governance console and hardened native system services.

Exit:
- daily-driver pilot on defined hardware;
- independent Trusted Core and native-kernel security review;
- measurable recovery objectives;
- signed release/update path preserves rollback and human recovery authority.

## Phase 6 — ARM64 Mobile Prototype

Deliver ARM64 boot/runtime support, Mobile shell, telephony/sensor/camera brokers, energy/background policy and secure-element integration.

Exit:
- common app/capability contracts work on Desktop and Mobile;
- continuity transfers state without silently transferring privilege;
- the same governance, audit and root-control contracts operate across x86_64 Desktop and ARM64 Mobile profiles.

## Long-term target

Routine implementation and maintenance may become predominantly AI-operated while C3/C4 authority, root keys, attribution, recovery and release evidence remain explicitly human governed.
