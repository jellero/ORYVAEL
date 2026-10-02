# ORYVAEL Roadmap

## Phase 0 — Architecture foundation

Deliver Constitution, trust model, schemas, Architecture Compiler skeleton, Rust workspace and CI.

Exit: schemas valid; crates compile/test; core invariants have test IDs.

## Phase 1 — Local Trusted Supervisor

Deliver principal identity, Linux sandbox integration, capability broker, audit service, local artifact store and policy CLI.

Exit:
- Developer AI writes only task workspace;
- enforceable network deny;
- every privileged operation has audit ID;
- agent cannot self-grant.

## Phase 2 — AI Development Factory

Deliver Architect/Developer/Test/Security/Reviewer roles, change-plan engine, proof-package generator, reproducible workers and SBOM service.

Exit: a C1 component is generated, independently verified and packaged end-to-end without AI host-admin access.

## Phase 3 — Immutable Desktop Prototype

Deliver bootable image, A/B updates, recovery, Desktop shell, app runtime, development workspace and dashboards.

Exit: fault-injected rollback works; app capability UI works; staged test-fleet rollout works.

## Phase 4 — Desktop Alpha

Deliver hardware matrix, GPU/Wayland path, secrets/passkeys, signed apps and user governance console.

Exit: daily-driver pilot on defined hardware and independent Trusted Core review.

## Phase 5 — ARM64 Mobile Prototype

Deliver Mobile shell, telephony/sensor/camera brokers, energy/background policy and secure-element integration.

Exit: common app/capability contracts work on Desktop and Mobile; continuity does not transfer privilege.

## Phase 6 — Kernel Decision

Evaluate Linux versus custom kernel using TCB size, vulnerabilities, driver burden, capability semantics, performance, energy, maintainability and formal-verification feasibility.

A custom kernel proceeds only if evidence justifies cost.

## Long-term target

Routine maintenance may be predominantly AI-operated while C3/C4 authority, root keys, attribution and release evidence remain under explicit human governance.
