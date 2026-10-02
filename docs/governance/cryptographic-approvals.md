# Cryptographic Human Release Approvals

C3 and C4 release authority must not be represented by a mutable string such as "approved by human".

ORYVAEL uses signed approval statements whose verification root is kept outside AI authority.

## Signed context

A release approval is bound to:
- change ID;
- change class;
- SHA-256 of the exact change-plan bytes;
- SHA-256 of the exact proof package;
- artifact name;
- SHA-256 of the exact artifact;
- rollout ring.

Changing any of those values invalidates the approval for the new release context.

## Root trust

The approval trust policy contains only public keys, signer identities, class authorization and thresholds.

A reference policy can require, for example:
- C3: one authorized human signer;
- C4: two distinct authorized human signers.

Duplicate signatures from one signer never satisfy a multi-person threshold.

The trust policy is itself a Root-of-Trust asset and must not be writable by AI principals.

## Keys

Reference signatures use Ed25519.

Private keys are not stored in this repository and should not be available to AI workers. Production keys should live in an HSM, secure element, offline signing workstation or equivalent human-controlled signer.

The reference CLI will include a signing helper for development/testing. That helper is not a recommendation to store production private keys on the ORYVAEL host.

## Canonical signature payload

ORYVAEL does not sign arbitrary JSON serialization.

The verifier constructs a domain-separated binary payload from fixed ordered fields, each encoded as an unsigned 64-bit big-endian byte length followed by the UTF-8 field bytes.

This avoids signature ambiguity from JSON whitespace or key ordering.

## Separation from proof

Verifier evidence answers: "did the candidate satisfy required technical checks?"

Human signature answers: "is this exact privileged candidate authorized to proceed?"

The human signature therefore belongs in release authorization, not in the AI-generated verifier evidence.
