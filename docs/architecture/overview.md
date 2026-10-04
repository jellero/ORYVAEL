# Architecture Overview

ORYVAEL is split into logical planes.

## Root of Trust and Human Governance

Contains constitutional policy, root signing keys, recovery authority, human approval identities and change-class rules. It changes rarely.

## Trusted Core

Deterministic mechanisms:
- capability broker;
- policy evaluator;
- identity verifier;
- audit writer/verifier;
- artifact/update verifier;
- architecture rule evaluator.

No LLM SDK is permitted here.

## AI Control Plane

Specialized principals:
- Architect AI;
- Developer AI;
- Test AI;
- Security AI;
- Reviewer AI;
- Dependency AI;
- Release AI;
- Operations AI;
- Documentation AI.

They are separate principals, not modes of an omnipotent process.

## Verification Plane

Produces compilation, test, fuzz, property, static-analysis, dependency, architecture, performance and formal-model evidence.

## System Services

Filesystem, network, secrets, display/audio, telemetry, updater and application lifecycle brokers.

The native system-service layer is still under construction. Existing Linux-hosted trusted-core services are reference/prototype implementations for governance, policy, proof and audit semantics; they are not part of the ORYVAEL product runtime boundary.

## Application Runtime

Applications execute with manifest-declared capabilities. Native, WASM and container-style workloads may coexist as product profiles evolve, but privileged access maps to the same capability and policy contract.

## Kernel and Hardware

ADR-0005 defines ORYVAEL as a bare-metal operating system with its own kernel and userland and supersedes the earlier Linux-first runtime direction.

The initial hardware target is x86_64 with UEFI used only for machine handoff. After `ExitBootServices`, ORYVAEL owns execution below the system-service boundary. Kernel responsibilities include memory management, interrupt handling, scheduling, IPC primitives, capability enforcement, isolation, device access and process lifecycle.

The current native foundation owns CR3 at the PML4 level, provides fresh ring-3 mappings, installs GDT/TSS and architectural exception gates, runs a 100 Hz timer interrupt path, exposes a DPL3 syscall gate and executes a first user payload at CPL3. During page-table migration, inherited lower-level supervisor mappings remain temporarily beneath the ORYVAEL-owned PML4 root.

Linux, macOS and Windows remain valid development hosts for compilation, image construction and virtualization. Host facilities are outside the ORYVAEL runtime and trust boundary.

## Critical control-flow rule

AI requests privileged actions. It does not directly mutate privileged system state.

~~~
AI request
 -> policy evaluation
 -> capability check
 -> supervised execution
 -> audit
 -> telemetry
~~~
