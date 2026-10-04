# ADR-0005: ORYVAEL is a bare-metal operating system

Status: Accepted

Supersedes: ADR-0001 for the product runtime architecture.

## Context

The product target is an operating system with its own kernel and userland. A Linux distribution, Linux kernel, container runtime or Linux init system underneath ORYVAEL changes the product boundary and is therefore not an acceptable runtime foundation.

The existing Linux trusted-core implementation remains useful as a host-side prototype for governance, proof, policy and audit semantics, but it is not the ORYVAEL operating system.

## Decision

ORYVAEL will own the machine below its system-service boundary.

The initial hardware target is x86_64 with UEFI firmware. UEFI is used only to obtain the platform memory map and transfer control. The Stage 0 kernel calls `ExitBootServices`; after that successful call, ORYVAEL executes without firmware boot services and without a host operating system.

The kernel, memory manager, interrupt handling, scheduler, IPC, capability enforcement and userland will be ORYVAEL components rather than Linux facilities.

Linux, macOS or Windows hosts may be used to compile images or run QEMU during development. Those host tools are outside the ORYVAEL runtime and trust boundary.

## Unsafe Rust exception

Bare-metal hardware and firmware boundaries necessarily require operations Rust cannot prove safe: UEFI FFI, raw firmware pointers, x86 port I/O, interrupt control and later page-table/descriptor-table manipulation.

`unsafe` is therefore permitted only inside narrowly scoped kernel hardware-boundary code when all of the following hold:

- the operation cannot be expressed with safe Rust at that boundary;
- the safety precondition is documented immediately next to the unsafe block;
- unsafe code does not become an authority bypass around higher-level ORYVAEL policy;
- higher-level kernel and userland code remains safe Rust by default.

## Consequences

Positive:
- ORYVAEL has an independent kernel/runtime identity;
- no Linux ambient-authority model is inherited as the product substrate;
- capability and AI-governance semantics can be enforced at native OS boundaries.

Negative:
- hardware enablement, memory management, interrupts, drivers and scheduling become project responsibilities;
- the usable hardware surface will initially be much smaller than Linux;
- security review must include architecture-specific unsafe code.

## Stage 0 acceptance criterion

A generated ORYVAEL image must boot under UEFI, acquire the firmware memory map, successfully terminate UEFI boot services, emit a serial marker from ORYVAEL-owned execution and remain alive in its own kernel idle loop.
