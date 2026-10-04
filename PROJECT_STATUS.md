# Project Status

ORYVAEL is currently a native minimal operating-system foundation plus a host-side trusted-core reference implementation. It is not yet a general-purpose or production-secure operating system.

ADR-0005 supersedes the earlier Linux-first product-runtime direction. Linux, macOS and Windows may still be used as development hosts, and the existing Linux trusted-core crates remain useful as reference/prototype infrastructure for governance, policy, proof and audit semantics, but no host kernel is part of the ORYVAEL runtime boundary.

## Native runtime present

- bootable x86_64 UEFI image;
- firmware memory-map capture and `ExitBootServices` handoff;
- physical 4 KiB frame allocator;
- fixed kernel heap;
- ORYVAEL-owned CR3/PML4 root, with inherited lower-level kernel mappings retained temporarily during migration;
- fresh user code/data/stack mappings without widening inherited supervisor mappings to user access;
- native GDT and TSS with a kernel privilege-transition stack;
- 32 architectural exception gates with fail-closed handling;
- 100 Hz PIT/PIC timer interrupt path;
- DPL3 syscall gate;
- first `init` payload executing at CPL3/ring 3;
- timer preemption observation while user code runs;
- capability-checked IPC mailbox roundtrip;
- minimal RAM filesystem with `/hello`;
- recovery kernel console with `help`, `mem`, `uptime`, `alloc`, `vm`, `ps`, `fs`, `ipc`, `clear`, `about` and `reboot`;
- QEMU/OVMF CI that builds the image, boots it and verifies the native userspace path.

## Trusted-core reference present

- trust and authority model;
- human-governance constitution;
- capability authorization model;
- change classification;
- security invariants;
- AI-native SDLC;
- machine-readable schemas;
- Rust reference components for policy, audit, control, supervision, tool brokering, proof, approvals, release and build flows;
- persistent trusted-service and audit foundations on the host-side reference path;
- CI gates for governance and security semantics.

## Not present yet

- complete ORYVAEL-owned lower-level kernel page tables for the full kernel virtual address space;
- recoverable per-process exception/fault termination;
- local APIC/IOAPIC interrupt routing;
- kernel threads, saved process contexts and context switching among multiple runnable ring-3 processes;
- general kernel object/handle tables, rights transfer and blocking IPC;
- persistent storage drivers and filesystem service;
- graphics/framebuffer/input stack;
- networking drivers and services;
- native system-service ports of governance, audit and root-control semantics;
- ARM64 boot path;
- hardened production capability broker and updater;
- hardware-backed roots of trust;
- production Desktop/Mobile shells;
- production telemetry and signed artifact registry;
- formal verification of the native implementation.

"Must" in architecture documents means a target requirement unless executable evidence demonstrates that the requirement is currently enforced. Documentation alone is not evidence.
