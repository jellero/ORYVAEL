# ADR-0002: Rust for Trusted Core

Status: Accepted

Trusted Core parses untrusted policy data and makes high-impact security decisions.

Decision:
- Rust is the reference implementation language;
- unsafe code is forbidden by default;
- unsafe requires a dedicated narrow ADR;
- AI/model SDKs remain outside Trusted Core;
- Trusted Core dependencies require T0 review.

AI workers may use other languages because they are sandboxed principals rather than part of root trust.
