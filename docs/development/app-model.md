# Application Model

## Package

An ORYVAEL application package contains:
- application identity;
- signed manifest;
- binaries/WASM/resources;
- presentation metadata;
- capability declarations;
- update metadata;
- provenance.

## Manifest-first generation

AI-generated applications begin with a manifest before code generation. The manifest defines the maximum requested authority.

Example:

~~~
application: screen-report
capabilities:
  - resource: screen
    actions: [capture]
    constraints:
      user_presence: true
  - resource: filesystem
    actions: [write]
    scope: ~/Reports/**
network:
  default: deny
background:
  allowed: false
~~~

## Installation

Installation verifies package signature, manifest schema, provenance and requested capabilities. User or enterprise policy may reduce the effective grant.

## Runtime

Privileged resources are brokered:
- filesystem;
- camera;
- microphone;
- network;
- notifications;
- secrets;
- sensors.

AI-generated updates follow the same proof/signature rules as human-authored updates. Locally generated code receives no implicit trust.
