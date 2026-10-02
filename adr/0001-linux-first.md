# ADR-0001: Linux-first implementation

Status: Accepted for prototype

## Context

ORYVAEL must validate AI governance, capability mediation, evidence and update semantics. Building a general-purpose kernel first would make hardware enablement dominate the project.

## Decision

Use Linux as the initial substrate and keep ORYVAEL security/application contracts above Linux-specific mechanisms.

## Consequences

Positive:
- immediate hardware ecosystem;
- namespaces/cgroups/seccomp/Landlock/eBPF are available;
- faster system prototype.

Negative:
- Linux ambient-authority concepts may leak into design;
- TCB remains large;
- some capability semantics require user-space mediation.

Review after Mobile prototype evidence.
