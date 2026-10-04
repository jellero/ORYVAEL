# Kernel Strategy

## Decision

ORYVAEL is a bare-metal operating system with its own kernel and userland.

ADR-0005 supersedes ADR-0001 for the product runtime architecture. Linux-first remains relevant only as historical sequencing and as a host-side reference/prototype environment for governance, policy, proof, audit and development-factory semantics.

## Product runtime boundary

The ORYVAEL product runtime does not depend on a Linux, macOS or Windows kernel underneath it. Development hosts may compile images, run tests and launch QEMU, but those hosts are outside the ORYVAEL runtime and trust boundary.

The kernel, memory manager, interrupt handling, scheduler, IPC, capability enforcement and userland are ORYVAEL components.

## Initial hardware target

The first target is x86_64 with UEFI firmware.

UEFI is used only for initial machine handoff:
- acquire the platform memory map;
- load the ORYVAEL image;
- terminate firmware boot services with `ExitBootServices`;
- continue under ORYVAEL-owned execution.

The current native foundation already provides:
- physical 4 KiB frame allocation;
- kernel heap;
- ORYVAEL-owned CR3/PML4 root;
- fresh ring-3 code/data/stack mappings;
- GDT and TSS;
- 32 architectural exception gates;
- 100 Hz PIT/PIC timer interrupts;
- DPL3 syscall entry;
- one CPL3 `init` payload;
- capability-checked mailbox IPC;
- minimal RAM filesystem;
- recovery kernel console;
- QEMU/OVMF boot verification in CI.

## Current migration constraints

The native runtime is intentionally minimal and not yet production-secure.

In particular:
- lower-level kernel mappings are still inherited beneath the ORYVAEL-owned PML4 root during migration;
- exception handling is currently fail-closed rather than recoverable per process;
- PIT/PIC remains the bootstrap interrupt path;
- user-code preemption is observed, but the kernel does not yet context-switch among multiple runnable processes;
- IPC is a fixed capability mailbox rather than a general kernel object/handle system;
- storage is RAM-only;
- graphics, input and networking are not implemented yet.

## Why the custom kernel is now the product direction

The product boundary requires capability and AI-governance semantics to be enforceable at native OS boundaries rather than inherited from an ambient-authority host operating system.

This choice increases project responsibility for hardware enablement, drivers, scheduling, memory management and architecture-specific unsafe code. The usable hardware surface will therefore grow incrementally.

## Rust and unsafe boundaries

Trusted components are written in Rust. Safe Rust remains the default.

`unsafe` is permitted only at narrowly scoped hardware, firmware and privilege-transition boundaries where the operation cannot be expressed safely, with local safety preconditions documented next to the unsafe operation. Unsafe code must not become an authority bypass around higher-level ORYVAEL policy.

## Near-term kernel priorities

1. Replace inherited lower-level kernel mappings with fully ORYVAEL-owned page tables.
2. Add recoverable per-process exception/fault termination.
3. Replace PIT/PIC bootstrap routing with local APIC and IOAPIC.
4. Add kernel threads, saved contexts and context switching between multiple runnable ring-3 processes.
5. Replace the fixed mailbox with kernel objects/handles, rights transfer and blocking IPC.
6. Add persistent storage and filesystem services.
7. Add graphics/input and networking drivers/services.
8. Port governance, audit and root-control semantics into native services.
9. Add ARM64 after the x86_64 kernel contracts stabilize.
