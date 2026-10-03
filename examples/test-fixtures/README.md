# Test-only cryptographic fixtures

Files in this directory exist only to make reference tests deterministic.

`DO_NOT_USE_IN_PRODUCTION-control-signing-key.hex` is a public, deterministic Ed25519 private seed. It provides no secrecy and no production authority.

A real ORYVAEL control-root private key must never be committed to the source repository, exposed to an AI workspace, or stored on the host that executes untrusted AI workloads. Production trust policy should contain public keys only; signing should happen through a separately governed offline/HSM-backed process.
