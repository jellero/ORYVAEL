# ORYVAEL bare-metal minimal base

This is the first minimally interactive ORYVAEL operating-system base. The guest does not run Linux, Debian, Ubuntu, Alpine or another host operating system.

The x86_64 image boots through UEFI only for the platform handoff. ORYVAEL captures the firmware memory map, calls `ExitBootServices`, installs its own kernel services and remains in control of the machine.

## What exists now

The minimal base provides:

- a freestanding Rust `no_std` kernel;
- direct x86_64 UEFI entry through `EFI/BOOT/BOOTX64.EFI`;
- retained firmware memory-map data after `ExitBootServices`;
- a native physical 4 KiB frame allocator built only from UEFI conventional memory;
- a small kernel bump heap owned by ORYVAEL;
- an ORYVAEL IDT with a native IRQ0 timer entry;
- 8259 PIC routing plus a 100 Hz PIT kernel clock for the current PC target;
- direct 16550/COM1 console I/O;
- polled PS/2 keyboard input for PC-compatible machines;
- a minimal interactive kernel console;
- a QEMU/OVMF integration test that boots the image and exercises live kernel commands.

The current console commands are:

```text
help
mem
uptime
alloc
clear
about
reboot
```

`alloc` intentionally exercises both the physical-frame allocator and kernel heap so the smoke test verifies more than boot output.

This is still a minimal kernel base, not a general-purpose OS. It does not yet provide ORYVAEL-owned page tables, exception recovery, preemptive multitasking, ring-3 processes, capability IPC, storage/filesystems, networking, graphics or native AI services.

## Host build requirements

The build machine needs:

- Rust 1.85 via `rustup`;
- the Rust `x86_64-unknown-uefi` target;
- `dosfstools` and `mtools` to assemble the UEFI image;
- QEMU and OVMF only for VM boot/testing.

Those are host-side development tools. They are not present in the ORYVAEL image.

On an Ubuntu/Debian development host, for example:

```sh
sudo apt-get install dosfstools mtools ovmf qemu-system-x86
```

That does not make ORYVAEL a Debian/Linux system. It only installs the compiler/test tooling on the machine building the image.

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

A successful boot reaches markers similar to:

```text
ORYVAEL: firmware boot services detached
ORYVAEL: bare-metal kernel online
ORYVAEL: physical allocator online regions=... free_pages=...
ORYVAEL: kernel heap online bytes=262144
ORYVAEL: timer interrupts online hz=100
ORYVAEL: minimal system ready

ORYVAEL OS minimal base
...
oryvael>
```

The default QEMU runner uses the serial terminal as the interactive console. Type `help` after the prompt.

## Runtime boundary

```text
hardware / QEMU
    ↓
UEFI firmware handoff
    ↓
ExitBootServices
    ↓
ORYVAEL kernel
    ├─ physical allocator
    ├─ kernel heap
    ├─ IDT + timer IRQ
    ├─ serial/keyboard input
    └─ kernel console
```

There is no Linux kernel or Linux distribution between firmware and ORYVAEL.

## Next native milestones

1. Own x86_64 page tables and virtual address spaces instead of retaining firmware mappings.
2. Add exception handlers and fault diagnostics for all architectural exceptions.
3. Replace the legacy PIT/PIC bootstrap clock with local APIC/IOAPIC routing.
4. Add kernel threads and a preemptive scheduler.
5. Enter ring 3 and launch the first ORYVAEL user process.
6. Implement capability-native IPC and system object handles.
7. Add storage, a filesystem service, framebuffer/graphics and networking.
