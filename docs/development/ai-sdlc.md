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
Formatting, compile, tests, static/security analysis, architecture checks, dependency analysis and risk-class-specific fuzz/property tests execute through capability-bound tools.

Verifier evidence is derived from the tamper-evident audit journal. For elevated changes, verifier principals must differ from the producer.

## 5. Proof package
Results become a structured evidence bundle with verifier identities, operation IDs, evidence hashes, source identity, artifact hashes and build provenance.

Release-grade C2/C3/C4 audited proofs require deterministic build provenance. A change that requests build:reproducible must also provide an independent build that matches source, toolchain, lockfile/SBOM and artifact identity.

## 6. Eligibility
Eligibility is deterministic. Mandatory verification failures are vetoes, not scores.

For C2/C3/C4, required passing verification must include evidence from a principal different from the producer. C3/C4 also require independent security-role evidence; C4 additionally requires independent reviewer-role evidence.

Human authority is enforced at the release gate. C3/C4 release approvals are cryptographically verified against a trust policy and bound to the exact change-plan hash, proof hash, artifact hash and rollout ring.

## 7. Artifact
Build produces content-addressed artifacts plus a deterministic build manifest and SBOM derived from locked dependency metadata. The actual artifact bytes are hashed by trusted code.

## 8. Staged rollout
Candidate progresses only through authorized rings. The release gate rebuilds the audited proof rather than trusting a serialized eligibility claim.

## 9. Runtime evidence
Crash, performance, resource, security and user-impact metrics are compared with thresholds.

## 10. Commit or rollback
Updater commits only after health conditions pass.

Operational telemetry can create a new change intent. It never directly authorizes source modification.
