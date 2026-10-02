# Security Invariants

Target properties. Mature implementations should map each invariant to executable tests or formal models.

- **INV-001 No self-grant:** a principal cannot widen its own authority.
- **INV-002 Human constitutional authority:** AI cannot modify constitutional rules or root keys.
- **INV-003 Deny by default:** unmatched privileged requests are denied.
- **INV-004 Deny precedence:** applicable explicit deny overrides allow.
- **INV-005 No self-approval:** producer cannot be sole mandatory verifier/releaser.
- **INV-006 Audit attribution:** privileged transitions identify principal and operation.
- **INV-007 Audit tamper evidence:** committed audit mutation/removal is detectable.
- **INV-008 Verified release:** required evidence exists before release eligibility.
- **INV-009 Architecture enforcement:** official builds reject forbidden dependencies.
- **INV-010 Capability confinement:** effective authority cannot exceed approved grants.
- **INV-011 Fail closed:** missing mandatory enforcement stops privileged execution.
- **INV-012 Recovery independence:** recovery does not depend on normal AI orchestration.
- **INV-013 Signer separation:** routine AI credentials cannot sign root artifacts.
- **INV-014 Rollback preservation:** an update commits only after health criteria pass.
- **INV-015 Evidence immutability:** implementation principals cannot rewrite completed mandatory verification evidence.
