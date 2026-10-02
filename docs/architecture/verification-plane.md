# Verification Plane

## Purpose

Generated code must be accompanied by evidence evaluated independently of the generating model.

## Evidence classes

### Build
- source commit;
- toolchain identity;
- dependency lock;
- build recipe;
- artifact hashes;
- reproducibility result.

### Correctness
- unit;
- integration;
- system;
- property;
- regression tests.

### Robustness
- fuzzing;
- malformed inputs;
- resource exhaustion;
- restart/recovery;
- fault injection.

### Security
- static analysis;
- dependency advisories;
- secret scanning;
- capability delta;
- attack-surface delta;
- sandbox boundary tests.

### Architecture
- dependency graph;
- layer policy;
- public API compatibility;
- Trusted Core size delta.

### Operations
- latency;
- memory;
- CPU;
- energy where measurable;
- crash behavior;
- rollback test.

## Proof package

A proof package should contain:
- change-plan hash;
- source hash;
- verifier identities;
- result hashes;
- architecture/security verdicts;
- benchmark deltas;
- artifact hashes;
- timestamps.

"Proof package" means evidence bundle. It is not a mathematical proof unless a specific formal method provides one.

## Veto semantics

A failed mandatory verifier makes the candidate ineligible. The implementation agent cannot edit a completed verifier result in place.
