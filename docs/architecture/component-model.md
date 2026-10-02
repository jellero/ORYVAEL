# Component Model and Architecture Compiler

Every privileged ORYVAEL component has a machine-readable descriptor.

## Descriptor fields

- stable component ID;
- architectural layer;
- owned source paths;
- required dependencies;
- allowed dependencies;
- forbidden dependencies;
- required capabilities;
- exposed capabilities;
- handled data classifications;
- network policy;
- change class;
- observability contract;
- restart/recovery behavior.

## Architecture Compiler

The Architecture Compiler evaluates the actual dependency graph against the declared architecture.

It must detect:
- unknown component dependencies;
- forbidden dependencies;
- prohibited layer edges;
- dependency cycles where the contract forbids them;
- privileged interface use without declaration;
- third-party dependencies forbidden in Trusted Core;
- unexpected capability expansion.

## Example

~~~
component: network-service
layer: system_service

depends_on:
  - ipc
  - crypto
  - network-hal

forbidden_dependencies:
  - ai-runtime
  - cloud-sdk
  - desktop-shell

exposes:
  - net.connect
  - net.listen

requires:
  - device.network
~~~

If an AI adds a model SDK to network-service, the official build pipeline rejects the architecture delta before merge.

## Ownership

Implementation ownership is not architectural authority. An AI may implement within an approved boundary without receiving the ability to redefine that boundary.
