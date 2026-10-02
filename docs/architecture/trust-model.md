# Trust Model

## R0 — Human Root

Constitutional signing, recovery and production root keys. AI processes must not possess these credentials.

## R1 — Trusted Core

Minimal deterministic enforcement. Dependency count and network access are aggressively constrained.

## R2 — Managed Agents

AI workers and orchestration. Powerful but treated as potentially faulty or adversarial.

## R3 — Applications

User, generated and plugin applications.

## R4 — External

Web, documents, remote APIs, model providers, registries and removable media.

## Boundary rule

Commands or data crossing from lower trust into higher-impact capability require deterministic mediation.

Requests carry:
- caller principal;
- action;
- target;
- delegated capability chain if any;
- change identifier if applicable.

## Delegation

Delegation is explicit, bounded, revocable and non-amplifying. A principal cannot delegate stronger authority than it owns.
