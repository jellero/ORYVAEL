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

The initial substrate is Linux. Kernel responsibilities remain deterministic: scheduling, memory, IPC primitives, isolation, device access and process lifecycle.

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
