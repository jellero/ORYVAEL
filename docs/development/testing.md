# Testing Strategy

An AI-maintained OS needs independent evidence dimensions.

## Families

**Unit:** deterministic component behavior.

**Integration:** broker/policy/audit/updater boundaries.

**Property:** invariants over generated inputs. Examples: deny precedence, non-amplifying delegation, monotonic audit sequence.

**Fuzzing:** manifests, IPC, policies, parsers and untrusted formats.

**Fault injection:** disk full, process kill, power loss, network partition, corrupt artifact, expired key and unavailable telemetry.

**Security boundary:** path traversal, capability escalation, cross-principal handle reuse, audit omission, malicious manifests and sandbox escape attempts.

**Performance:** boot, launch, policy latency, IPC, battery/energy, memory and update duration.

**Reproducibility:** independent workers build the same source and compare artifacts or normalized reproducibility evidence.

## Ownership

Mandatory test artifacts are protected. A developer agent may propose tests, but elevated release policy can require an independent verifier to reproduce them.

A regression beyond a mandatory threshold is a failed verifier, not a warning the implementation agent may ignore.
