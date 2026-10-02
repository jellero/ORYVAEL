# Kernel Strategy

## Decision

The first ORYVAEL implementation is Linux-first. This is a sequencing decision, not a commitment that Linux must remain the final kernel.

## Rationale

A new general-purpose kernel requires extensive ownership of GPU, Wi-Fi, Bluetooth, storage, USB, power management, suspend/resume, ACPI/device trees and mobile modem integration. Those tasks are largely orthogonal to the core ORYVAEL hypothesis: AI development under deterministic governance.

The project should validate governance, capabilities, audit, build evidence and application contracts before taking ownership of the complete driver ecosystem.

## Initial substrate

Desktop reference:
- Linux kernel;
- immutable root filesystem;
- image/A-B updates;
- Wayland-compatible display stack;
- minimized system services around ORYVAEL brokers.

Mobile reference:
- Linux/Android-compatible kernel substrate when hardware enablement requires it;
- ORYVAEL user-space trust model above the hardware layer;
- long-term security semantics defined by ORYVAEL rather than Android permissions.

## Kernel-facing controls

The Trusted Core may combine:
- namespaces;
- cgroups v2;
- seccomp;
- Landlock;
- eBPF for observation/enforcement where justified;
- LSM integration in later phases.

No single mechanism is assumed to provide complete isolation.

## Custom-kernel decision gate

A custom kernel is considered only if evidence shows material benefit in:
- trusted computing base size;
- isolation simplicity;
- capability-native IPC;
- update/recovery;
- attack surface;
- maintainability;
- formal verification.

A custom kernel is not a branding milestone.
