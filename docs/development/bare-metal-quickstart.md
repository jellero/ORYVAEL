# ORYVAEL native bare-metal base

This is a native ORYVAEL operating-system base. The guest does not run Linux, Debian, Ubuntu, Alpine or another host operating system.

The x86_64 image boots through UEFI only for the platform handoff. ORYVAEL captures the firmware memory map, calls `ExitBootServices`, switches to its own top-level page table, installs its own privilege/interrupt structures, runs a first process at CPL3 and remains in control of the machine.

## What exists now

The native base provides:

- a freestanding Rust `no_std` kernel;
- direct x86_64 UEFI entry through `EFI/BOOT/BOOTX64.EFI`;
- retained firmware memory-map data after `ExitBootServices`;
- a native physical 4 KiB frame allocator built from UEFI conventional memory;
- a kernel bump heap owned by ORYVAEL;
- an ORYVAEL-owned PML4 root loaded into CR3;
- a fresh user page-table branch with separate ring-3 code, data and stack mappings;
- an ORYVAEL GDT and TSS with a dedicated kernel privilege-transition stack;
- 32 architectural exception gates with fail-closed diagnostics;
- a DPL3 `int 0x80` syscall gate;
- 8259 PIC routing plus a 100 Hz PIT clock for the current bootstrap PC target;
- a first `init` payload that actually executes at CPL3;
- timer preemption/accounting while `init` is executing in user mode;
- capability-checked mailbox IPC;
- a minimal RAM filesystem containing `/hello`;
- direct 16550/COM1 console I/O and polled PS/2 input;
- a recovery kernel console;
- a QEMU/OVMF integration test that boots and exercises all of these boundaries.

The recovery console commands are:

```text
help
mem
uptime
alloc
vm
ps
fs
ipc
clear
about
reboot
```

`vm` reports the ORYVAEL CR3 and user address-space base. `ps` reports the completed ring-3 init and how many timer interrupts preempted it. `fs` exposes the RAMFS test file, and `ipc` reports the capability-mailbox state.

## Important current limits

The kernel owns the top-level PML4 and its fresh user branch, but lower-level kernel mappings inherited at UEFI handoff are still retained beneath the new root. They will be rebuilt natively in the next VM milestone.

The timer can interrupt a user process and the test proves that privilege transition, but the current scheduler boundary runs one `init` process to completion. It does not yet save/restore several runnable process contexts.

The current exception gates stop the system fail-closed with diagnostics. Per-process fault recovery/termination is not yet implemented.

The filesystem is RAM-only. There are no persistent storage drivers, framebuffer desktop, networking stack or native AI services yet.

## Host build requirements

The build machine needs:

- Rust 1.85 via `rustup`;
- the Rust `x86_64-unknown-uefi` target;
- `dosfstools` and `mtools` to assemble the UEFI image;
- QEMU and OVMF only for VM boot/testing.

Those are host-side development tools. They are not present in the ORYVAEL image. On an Ubuntu/Debian development host, for example:

```sh
sudo apt-get install dosfstools mtools ovmf qemu-system-x86
```

This command affects only the development host. There is no Linux distribution in the ORYVAEL runtime image.

## Build

```sh
./scripts/build-os.sh
```

Outputs:

```text
dist/oryvael-x86_64-uefi.img
dist/BOOTX64.EFI
```

## Boot in QEMU

```sh
./scripts/run-os.sh
```

A successful native-userspace boot includes markers similar to:

```text
ORYVAEL: firmware boot services detached
ORYVAEL: bare-metal kernel online
ORYVAEL: physical allocator online regions=... free_pages=...
ORYVAEL: kernel heap online bytes=262144
ORYVAEL: page tables online cr3=0x...
ORYVAEL: exceptions online vectors=32
ORYVAEL: timer interrupts online hz=100
ORYVAEL: userspace mappings online base=0x0000400000000000
ORYVAEL: syscall console online vector=0x80
ORYVAEL: userspace init entering ring3
ORYVAEL: ring3 init online
ORYVAEL: capability IPC roundtrip value=42
ORYVAEL: ramfs read /hello bytes=25
hello from ORYVAEL ramfs
ORYVAEL: init exited code=0 preemptions=...
ORYVAEL: native minimal OS ready

ORYVAEL OS native base
oryvael>
```

The default QEMU runner uses the serial terminal as the interactive recovery console.

## Runtime boundary

```text
hardware / QEMU
    ↓
UEFI firmware handoff
    ↓
ExitBootServices
    ↓
ORYVAEL kernel (CPL0)
    ├─ physical allocator + kernel heap
    ├─ ORYVAEL CR3 / PML4 root
    ├─ GDT + TSS + exceptions + timer
    ├─ syscall / capability boundary
    ├─ RAMFS
    └─ ring-3 address space
              ↓
         ORYVAEL init (CPL3)
```

There is no Linux kernel or Linux distribution between firmware and ORYVAEL.

## Next native milestones

1. Replace all inherited lower-level kernel mappings with ORYVAEL-built page tables.
2. Turn user faults into process termination/recovery instead of a whole-kernel fail-closed halt.
3. Replace legacy PIT/PIC with local APIC/IOAPIC routing.
4. Save/restore contexts and schedule multiple runnable ring-3 processes.
5. Generalize the capability mailbox into kernel objects, rights and blocking IPC.
6. Add persistent storage and a filesystem service.
7. Add framebuffer/graphics and networking.
