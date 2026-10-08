# ORYVAEL Embedded / Edge

## Purpose

ORYVAEL Embedded extends the ORYVAEL authority model to IoT, robotics and other
physical-world devices. The profile is not a reduced Desktop port and does not
assume that an AI model runs on the device.

The device is an independent enforcement point. Remote or local AI components
may request actions, but deterministic device-side policy decides whether those
actions are permitted.

The core invariant remains:

> Intelligence may propose actions; authority remains explicitly granted,
> constrained, attributable and revocable.

## Primary use cases

- industrial sensors and actuators;
- home/building automation;
- robotics and autonomous platforms;
- gateways between AI control planes and field buses;
- energy, environmental and infrastructure controllers;
- constrained devices that need signed updates, device identity and auditable
  capability enforcement.

## Product classes

### Embedded MCU

For microcontrollers with constrained RAM, flash and power budgets.

Expected properties:
- Rust `no_std` trusted runtime;
- static or tightly bounded memory allocation;
- hardware abstraction layer for timers, GPIO, buses and network peripherals;
- secure/verified boot where supported;
- device identity backed by hardware keys or a secure element where available;
- deterministic capability checks before hardware access;
- bounded append-only audit records with export/checkpoint support;
- signed A/B or recovery-capable firmware update flow where hardware permits;
- no requirement for an on-device LLM.

RISC-V MCUs, including devices in the ESP32 family, are candidates for the
first experimental implementation. ESP32 support is an architecture port, not
a compilation target for the existing x86_64 kernel.

### Edge node

For more capable embedded boards and gateways.

Expected properties:
- all Embedded MCU authority guarantees;
- richer networking and persistent storage;
- multiple isolated workloads;
- optional WASM application runtime;
- stronger local observability and audit retention;
- protocol brokers for interfaces such as CAN, Modbus, SPI, I2C and GPIO;
- optional local inference as an untrusted workload, never as the authority
  mechanism.

## Authority boundary

A typical deployment is:

~~~
AI / operator / automation
          |
   authenticated request
          |
          v
+--------------------------+
| ORYVAEL Embedded / Edge  |
|                          |
| identity                 |
| capability policy        |
| safety constraints       |
| audit                    |
| update verification      |
| hardware brokers         |
+------------+-------------+
             |
             v
      physical hardware
~~~

An AI request to operate hardware is treated like any other untrusted request.
The runtime checks the principal, capability, resource scope and relevant local
safety policy before dispatching the operation.

Example:

~~~
request: valve.open(resource = "valve-3")
principal: maintenance-agent

required capability: actuator.valve.open
allowed resources: valve-1, valve-2

result: DENIED
reason: resource outside granted scope
audit: principal + request + decision + policy version
~~~

A remote control plane therefore cannot gain new physical authority merely by
producing convincing natural-language output.

## Runtime split

The current native kernel contains x86_64-specific boot, privilege, interrupt,
memory-management and device code. Embedded targets require a separate
architecture/backend layer.

The intended split is:

~~~
                       ORYVAEL contracts
                  capability / IPC / audit
                            |
             +--------------+--------------+
             |                             |
        arch/x86_64                    arch/riscv32
             |                             |
       UEFI / PC HAL                 MCU / SoC HAL
             |                             |
  APIC/PCI/storage/etc.         timer/GPIO/buses/network
~~~

The first embedded implementation should reuse semantics, data formats and
security invariants before attempting broad code reuse.

## Components expected to be portable

Portable or adaptable components include:
- principal and device identity contracts;
- capability naming and authorization semantics;
- policy evaluation rules;
- IPC/object authorization model;
- audit event format and hash/checkpoint semantics;
- signed control/update artifacts;
- recovery and rollback policy;
- remote management protocol contracts.

Hardware-specific components include:
- reset/boot entry;
- exception and interrupt handling;
- privilege transitions and isolation primitives;
- memory protection/MMU/PMP configuration;
- timers and watchdogs;
- flash/storage drivers;
- Ethernet/Wi-Fi and radio integration;
- GPIO, UART, SPI, I2C, CAN and field-bus drivers.

## Isolation model

Embedded hardware does not necessarily provide the same isolation primitives
as x86_64. The implementation must preserve the security contract without
pretending that all targets provide equivalent mechanisms.

Depending on the target, isolation may use:
- RISC-V privilege levels and PMP;
- MMU-backed address spaces on capable SoCs;
- MPU/PMP regions for trusted/untrusted compartments;
- process isolation on larger Edge systems;
- static partitioning when hardware cannot support dynamic isolation.

A target that cannot enforce a required authority boundary must declare that
limitation explicitly rather than silently weakening the contract.

## Networking model

Embedded networking is brokered rather than ambient.

Workloads and remote agents receive explicit network capabilities describing:
- allowed peers or services;
- allowed protocols;
- inbound versus outbound authority;
- credential/key access;
- rate and resource ceilings where relevant.

Remote administration must not imply actuator authority. Management,
telemetry and physical-control capabilities remain separate.

## Update and recovery

The Embedded profile requires fail-closed update verification.

An update path should provide, where hardware permits:
- authenticated firmware manifests;
- artifact hash verification;
- signer authorization under the ORYVAEL root policy;
- anti-rollback state;
- staged activation;
- watchdog-assisted recovery;
- last-known-good or A/B fallback;
- audit evidence for update acceptance and activation.

The exact mechanism is target-specific, but an AI component may not sign,
approve or expand the authority of its own firmware update.

## Relationship to AI

No local model is required. A useful ORYVAEL Embedded device can contain no AI
runtime at all.

AI may run:
- remotely in the ORYVAEL control plane;
- on a nearby gateway;
- locally on a sufficiently capable Edge node as an untrusted workload.

In every case, deterministic policy remains authoritative.

## Initial implementation direction

The first prototype should target one RISC-V MCU/SoC and prove the authority
boundary before broadening hardware support. An ESP32-P4-class target is a
reasonable experimental candidate because it provides a modern RISC-V platform
and useful embedded peripherals, but the architecture must not depend on one
vendor.

Prototype milestones:
1. boot a Rust `no_std` ORYVAEL Embedded runtime;
2. initialize serial console, timer and watchdog;
3. establish device identity;
4. implement a minimal capability object table;
5. broker one GPIO or simulated actuator operation;
6. deny an unauthorized operation and emit an audit record;
7. add authenticated network control;
8. verify a signed firmware/update manifest;
9. demonstrate recovery from a rejected or failed update;
10. add a second hardware target to validate the abstraction boundary.

## Non-goals

ORYVAEL Embedded does not aim to:
- reproduce the Desktop UI on a microcontroller;
- run a general-purpose container stack on every MCU;
- require an LLM on constrained hardware;
- expose raw hardware access to remote AI agents;
- claim x86_64-equivalent isolation on hardware that cannot provide it;
- replace deterministic safety interlocks with probabilistic AI judgment.
