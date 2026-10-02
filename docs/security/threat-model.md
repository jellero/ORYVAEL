# Threat Model

## Protected assets

- constitutional/root signing keys;
- recovery authority;
- private user data;
- credentials and secrets;
- system integrity;
- release artifacts;
- audit history;
- build provenance;
- availability of recovery paths.

## Adversaries

### Faulty AI
Incorrect non-malicious model behavior.

### Manipulated AI
Prompt injection, poisoned context or malicious tool output redirects an agent.

### Compromised provider
A model, package, CI or cloud provider behaves maliciously.

### Malicious application
An app attempts privilege escalation, persistence or exfiltration.

### Supply-chain attacker
A dependency, toolchain or artifact is replaced.

### Local attacker
Low-privilege code attempts to cross a broker or sandbox boundary.

### Privileged insider
A legitimate human identity abuses assigned authority.

## Representative threats

**AI writes outside task scope:** isolated workspace, brokered filesystem, scoped grant, audit.

**AI changes tests to conceal a bug:** protected mandatory verifiers, separate verifier identity, immutable result artifact.

**Agent requests more privilege:** no self-grant path; change-class escalation.

**Prompt injection requests secrets:** secret access is decided outside model reasoning by deterministic capability policy.

**Audit tampering:** protected writer, hash chaining, append-oriented storage and later external checkpoints.

**Dependency compromise:** lock, hashes, SBOM, advisories, reproducibility and TCB dependency budget.

**Malicious release:** proof-package eligibility, signing separation, staged rollout and rollback.

## Residual risk

ORYVAEL cannot eliminate implementation bugs in the Trusted Core, firmware compromise, stolen human root credentials, cryptographic defects or correlated failures among reviewers. Residual risk must be stated explicitly rather than hidden behind model confidence.
