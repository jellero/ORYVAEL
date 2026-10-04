# ADR-0001: Linux-first implementation

Status: Superseded by ADR-0005 for the product runtime architecture

## Context

ORYVAEL must validate AI governance, capability mediation, evidence and update semantics. Building a general-purpose kernel first would make hardware enablement dominate the project.

## Historical decision

Linux was selected as an initial prototype substrate so governance, policy, evidence and release semantics could be exercised quickly.

## Current interpretation

The Linux implementation is retained only as a host-side/reference prototype. It is not an acceptable ORYVAEL OS runtime foundation and does not define the product kernel or userland boundary.

ADR-0005 establishes the current product direction: an ORYVAEL-owned bare-metal kernel and userland with no Linux kernel underneath.
