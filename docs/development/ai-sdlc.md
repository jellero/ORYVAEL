# AI-Native SDLC

## 0. Intent
A human requirement, bug, telemetry regression or approved research objective receives an immutable change ID.

## 1. Change plan
Planning declares scope, components, tools, capabilities, dependencies, architecture delta, tests, rollout ceiling and rollback.

## 2. Isolated workspace
Supervisor creates a scoped worktree/filesystem, resource budget, network policy, tool allowlist and limited credentials.

## 3. Implementation
Developer AI writes only in its workspace. Tool invocations receive operation IDs.

## 4. Independent verification
Formatting, compile, tests, static/security analysis, architecture checks, dependency analysis and risk-class-specific fuzz/property tests.

## 5. Proof package
Results become a structured evidence bundle with verifier identities, operation IDs, evidence hashes, source identity and artifact hashes.

The reference proof engine rejects malformed hashes, records every failed verifier as a veto reason and requires every verifier named in the change plan to have passing evidence.

## 6. Eligibility
Eligibility is deterministic. For C2/C3/C4, required passing verification must include evidence from a principal different from the producer. C3/C4 additionally require a human-approval reference. This reference is not yet equivalent to a cryptographically verified human signature; signature verification is a later release-gate hardening step.

## 7. Artifact
Build creates content-addressed artifact, SBOM and provenance.

## 8. Staged rollout
Candidate progresses only through authorized rings.

## 9. Runtime evidence
Crash, performance, resource, security and user-impact metrics are compared with thresholds.

## 10. Commit or rollback
Updater commits only after health conditions pass.

Operational telemetry can create a new change intent. It never directly authorizes source modification.
