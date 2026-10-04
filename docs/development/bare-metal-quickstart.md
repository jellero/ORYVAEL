# ORYVAEL bare-metal Stage 0

This is the first bootable ORYVAEL OS substrate. The guest does not run Linux, Debian, Ubuntu, Alpine or another host operating system.

The x86_64 image boots through UEFI firmware only long enough to receive the platform handoff. The kernel then acquires the UEFI memory map, calls `ExitBootServices`, disables interrupts until its own IDT exists, reports the handoff over COM1 and enters an ORYVAEL-owned idle loop.

## What exists now

Stage 0 provides:

- a freestanding `no_std` Rust kernel;
- direct x86_64 UEFI entry without a Linux loader;
- firmware memory-map capture;
- explicit `ExitBootServices` transition;
- direct 16550/COM1 serial output through x86 port I/O;
- a bootable FAT UEFI image with `EFI/BOOT/BOOTX64.EFI`;
- a QEMU/OVMF smoke test that proves execution continues after firmware boot services are gone.

It does not yet provide virtual memory management, an IDT/APIC interrupt path, a scheduler, processes, user mode, filesystems, drivers or the final AI/capability services. Those are kernel milestones, not delegated Linux facilities.

## Host build requirements

The build machine needs:

- Rust 1.85 via `rustup`;
- the Rust `x86_64-unknown-uefi` target;
- `dosfstools` and `mtools` to assemble the UEFI system image;
- QEMU and OVMF only if you want to boot the image in a VM.

These are development tools on the host. They are not present inside the ORYVAEL guest image.

On Ubuntu/Debian build hosts the packages are typically:

```sh
sudo apt-get install dosfstools mtools ovmf qemu-system-x86
```

That command installs tooling on the development machine; ORYVAEL itself contains no Debian root filesystem.

## Build

```sh
./scripts/build-os.sh
```

Outputs:

```text
dist/oryvael-x86_64-uefi.img
dist/BOOTX64.EFI
```

The raw image contains the UEFI fallback path:

```text
EFI/BOOT/BOOTX64.EFI
```

## Boot in QEMU

```sh
./scripts/run-os.sh
```

A successful Stage 0 boot prints markers including:

```text
ORYVAEL: firmware boot services detached
ORYVAEL: bare-metal kernel online
ORYVAEL: no Linux kernel; entering kernel idle
```

QEMU continues running because the kernel is intentionally alive in its own idle loop. Stop the VM with `Ctrl-C`.

## Runtime boundary

The runtime chain is:

```text
hardware / QEMU
    ↓
UEFI firmware handoff
    ↓
ORYVAEL kernel
    ↓
future ORYVAEL kernel services and userland
```

There is no Linux kernel or Linux distribution between the firmware and ORYVAEL.
