# AI Control Plane

ORYVAEL uses multiple constrained AI principals instead of one universal agent.

## Architect AI

May analyze requirements, propose ADRs, create architecture deltas and identify affected invariants.

Cannot approve C4 constitutional changes or directly modify production.

## Developer AI

May read scoped source, write a change workspace and execute approved compiler/test tools.

Cannot merge, sign releases, alter verification policy or access unrelated private data.

## Test AI

May generate and run tests, fuzzers, property checks and coverage analysis.

For elevated changes, it must be independently identifiable from the implementation principal.

## Security AI

May perform threat analysis, capability-delta review, dependency review and adversarial testing.

It may fail a mandatory security gate. It cannot waive one.

## Reviewer AI

Compares intent, architecture, implementation and evidence, producing a structured review artifact.

## Dependency AI

Tracks provenance, versions, vulnerabilities, duplicate functionality and removal candidates.

It may propose upgrades; sensitive dependency expansion follows change classification.

## Release AI

May assemble an eligible candidate, validate metadata and propose rollout rings.

It does not possess constitutional or production-root signing keys.

## Operations AI

May read scoped telemetry, diagnose incidents, propose rollback/repair and execute explicitly pre-authorized low-risk remediation.

It cannot erase telemetry or audit history.

## Documentation AI

Maintains architecture references, API docs and traceability links. Documentation changes do not automatically modify executable policy.

## Separation of duties

Each role has:
- a distinct principal ID;
- a maximum capability envelope;
- task-scoped grants;
- separate audit identity.

The same model provider may technically power multiple roles, but authorization does not collapse those roles into one principal. Higher-assurance deployments can require independent models or toolchains for critical verification.
