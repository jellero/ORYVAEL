# Dependency Policy

## Goals

Deterministic builds, small Trusted Core, explicit provenance and controlled complexity.

## Classes

### T0 — Trusted Core
Requires explicit justification, maintained upstream, version lock, vulnerability monitoring and minimal runtime behavior.

### T1 — System service
Locked and included in SBOM. Large frameworks require an ADR.

### T2 — AI worker
May use model/provider SDKs because it executes outside Trusted Core. Still pinned and sandboxed.

### T3 — Application
Governed by application build and sandbox policy.

## Prohibited patterns

- floating versions in release builds;
- download-and-execute during normal build;
- hidden plugin discovery in Trusted Core;
- runtime code from arbitrary URLs;
- duplicate trusted dependencies without justification.

## Complexity budget

Sensitive components may set maximum direct dependencies, public interfaces, privileged capabilities and trusted source size. Exceeding a budget escalates review instead of silently growing the TCB.
