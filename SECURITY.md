# Security Policy

ORYVAEL is pre-production research software. The current reference implementation is not a hardened security boundary.

## Principles

- fail closed for mandatory controls;
- deny by default;
- least privilege;
- human-controlled root of trust;
- separation of duties;
- tamper-evident audit;
- reproducible build evidence;
- no AI self-approval;
- no silent security downgrade;
- rollback for deployed mutable state.

## High-priority vulnerability classes

- capability escalation;
- policy bypass;
- audit forgery or truncation;
- provenance/signature bypass;
- sandbox escape;
- unauthorized private-data or secret access;
- update rollback bypass;
- cross-principal confused deputy.

Maintainers should enable GitHub private vulnerability reporting before external security testing begins.
