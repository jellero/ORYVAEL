# Change Classification

## C0 — Informational
Documentation, diagrams and non-executable metadata. May be highly automated.

## C1 — Routine
Isolated implementation, non-privileged UI, internal refactor or performance work without privilege expansion.

Required: tests, architecture check, dependency check. Can become autonomously mergeable under explicit policy.

## C2 — Elevated
System service changes, new capability use, network expansion, persistent formats or sensitive dependencies.

Required: independent review, security checks, integration tests and rollback plan.

## C3 — Critical
Capability broker, identity, secrets, audit, sandbox, updater verification, release signing pipeline or kernel-facing security.

Required: human approval, independent security evidence, fault injection, recovery test and signed proof package.

Never autonomous.

## C4 — Constitutional
Constitution, root-key policy, human approval rules, maximum AI authority or mechanisms that can disable mandatory audit.

Requires explicit human governance and protected signing. Never autonomous.
