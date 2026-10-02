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
- real Linux confinement smoke test in CI;
- negative tests for network self-grant and worker-writable control files.

Phase 1 exit criteria and current evidence:
- Developer AI writes only the task workspace: verified by real sandbox smoke test.
- Network deny is enforceable: verified by real socket attempt inside the sandbox.
- Every privileged operation has an audit ID: verified by audit assertions in CI.
- Agent cannot self-grant: verified by requesting host networking under an explicit network deny and requiring rejection.

Hardening carried into Phase 1.x / Phase 2:
- persistent supervisor daemon/service interface;
- single-owner centralized audit service and external checkpoints;
- distribution/hardware compatibility matrix;
- seccomp/Landlock defense in depth;
- cgroup-v2 accounting and lifecycle cleanup.

## Phase 2 — AI Development Factory

Next target.

Deliver:
- brokered Tool Executor;
- Architect, Developer, Test, Security and Reviewer principals;
- immutable change-plan binding;
- proof-package generator;
- protected verifier results;
- Git branch/worktree broker;
- compiler/test/fuzz broker;
- reproducible build workers;
- dependency/SBOM service;
- release eligibility engine.

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
