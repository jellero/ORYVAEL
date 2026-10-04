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

## Application Runtime

Applications execute with manifest-declared capabilities. Native, WASM and container workloads may coexist but privileged access maps to the same policy contract.

## Kernel and Hardware

The product substrate is the ORYVAEL bare-metal kernel. The current x86_64
UEFI implementation owns memory, privilege transitions, exceptions, timer
interrupts, syscalls, capability IPC and the RTL8139 network device after
terminating UEFI boot services.

Linux remains only a development-host and reference-prototype environment for
the existing Trusted Core crates. Linux mechanisms do not sit below the
ORYVAEL guest and are not part of the product runtime boundary.

The current native image is a kernel foundation, not yet the complete plane
stack described above. In particular, the AI Control Plane, deterministic
policy services and model inference runtime have not yet migrated into native
ring-3 services.

## Critical control-flow rule

AI requests privileged actions. It does not directly mutate privileged host state.

~~~
AI request
 -> policy evaluation
 -> capability check
 -> supervised execution
 -> audit
 -> telemetry
~~~
