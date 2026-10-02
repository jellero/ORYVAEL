# ADR-0003: Capability-first authorization

Status: Accepted

ORYVAEL uses explicit scoped capabilities as the primary application/agent authorization abstraction.

Traditional users/groups/root may exist in the Linux compatibility layer but do not define the ORYVAEL contract.

Rules:
- deny by default;
- explicit deny wins;
- scope is structured;
- delegation cannot amplify;
- grants are attributable and revocable;
- AI cannot self-grant.
