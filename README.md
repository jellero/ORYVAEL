# ORYVAEL

ORYVAEL is a research and engineering project for an AI-native operating system in which artificial intelligence can design, implement, test, integrate and maintain software while authority remains explicitly under human control.

The project does not assume that an AI becomes trustworthy enough to receive unrestricted administrator access. The architecture assumes the opposite: AI components are powerful but untrusted principals. Their actions must be scoped, observable, attributable, reproducible and reversible.

## Core thesis

**ORYVAEL separates intelligence from authority.**

An AI may analyze requirements, propose architecture, write code, create tests, run builds, perform security analysis, prepare release candidates, diagnose failures and propose repairs.

An AI may not implicitly grant capabilities to itself, change constitutional policy, modify the root of trust, disable audit, bypass mandatory verification, sign privileged releases or expand its own production scope.

## System planes

~~~
Human Governance
      |
Constitution / Root of Trust
      |
AI Control Plane
      |
Verification + Policy Plane
      |
System Services / Application Runtime
      |
Kernel / Hardware
~~~

Observability and cryptographic audit cross every plane.

## Product profiles

### ORYVAEL Desktop

For workstations and general-purpose PCs:
- full windowed desktop;
- isolated developer workspaces;
- local AI agents;
- container/WASM workloads;
- explicit professional/admin capabilities;
- x86-64 and ARM64 targets.

### ORYVAEL Mobile

For phones and mobile devices:
- ARM64 first;
- touch-first shell;
- aggressive energy/resource budgets;
- secure-element identity;
- telephony, camera and sensor capabilities;
- the same app, capability and audit contracts as Desktop.

The user experience differs. The trust model does not.

## Repository map

- docs/vision.md — product vision
- docs/principles.md — engineering principles
- docs/architecture/ — system design
- docs/security/ — threat model and invariants
- docs/governance/ — human authority
- docs/development/ — AI-native SDLC
- docs/roadmap.md — staged implementation
- adr/ — architecture decision records
- spec/ — machine-readable contracts
- crates/ — Rust trusted-core reference
- examples/ — example policies and manifests

## Trust zones

| Zone | Examples | Default |
|---|---|---|
| Root of Trust | constitutional policy, signing roots, recovery | human-controlled |
| Trusted Core | policy, audit, capability broker, artifact verifier | minimal deterministic code |
| Managed Intelligence | developer/test/security/release AI | untrusted, scoped |
| Untrusted Workload | apps, plugins, documents, web content | sandboxed |

No AI model belongs to the Root of Trust.

## Privileged change flow

~~~
human intent / issue
        |
     change plan
        |
architecture validation
        |
 capability grant
        |
 AI implementation
        |
independent verification
        |
   proof package
        |
 deterministic policy
        |
 release candidate
        |
 staged rollout
        |
 telemetry + audit
~~~

The implementation agent cannot approve its own change.

## Reference strategy

The initial implementation is Linux-first to validate the control model without first rebuilding the entire hardware ecosystem. ORYVAEL contracts remain above Linux-specific mechanisms so a custom kernel remains a later evidence-based decision.

Trusted reference components are written in Rust with unsafe code forbidden unless a dedicated ADR permits a narrowly reviewed exception.

## Current status

Phase 0 is implemented and the Phase 1 Local Trusted Supervisor is running as an alpha reference. CI now executes the real Linux sandbox and verifies workspace confinement, network denial, architecture policy and tamper-evident audit behavior. ORYVAEL is still not a bootable or production-secure OS.

## Immediate milestones

1. Build the Phase 2 Tool Broker for Git, compiler, tests and fuzzing.
2. Bind every AI change to an immutable change plan.
3. Generate proof packages from independent verifier results.
4. Add reproducible build workers and SBOM generation.
5. Add persistent supervisor/audit services and external audit checkpoints.
6. Integrate metrics, logs and traces.
7. Build an immutable Desktop developer image.
8. Validate the same contracts on ARM64 Mobile.

## License

No license file is currently committed. A project license should be selected deliberately before accepting external code contributions.
