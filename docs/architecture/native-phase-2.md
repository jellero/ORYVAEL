# Native Phase 2 — Identity, Isolation & Native Intelligence

Status: design target for the next native-runtime milestone.

This document defines the second native-runtime phase of ORYVAEL. It is intentionally separate from the historical host-reference roadmap phases, where “Phase 2” refers to the Linux-hosted AI Development Factory. In this document, **Native Phase 2** means the next stage of the bare-metal product runtime after the current x86_64 kernel, networking and SSH foundation.

## Objective

Native Phase 2 turns ORYVAEL from a bootable kernel with vertical demonstrations into a reusable authority substrate for real services, applications and AI principals.

The ordering is deliberate:

1. establish process isolation;
2. establish kernel objects and non-forgeable handles;
3. enforce capabilities and identities;
4. add sandbox/resource boundaries;
5. establish entropy, secrets and key lifecycle;
6. establish authenticated sessions and attributed audit;
7. only then run native AI principals inside the system.

The AI must enter a system that already knows how to constrain it. AI capability never implies authority.

## Security rules

Native Phase 2 must preserve the existing ORYVAEL invariants:

- deny by default;
- no principal may widen its own authority;
- no AI principal belongs to the root of trust;
- implementation and approval remain separable;
- privileged operations are attributable and auditable;
- failure of mandatory enforcement fails closed;
- recovery remains independently available to humans.

Unix-style UIDs, groups and permission bits may be exposed later as a compatibility surface, but they are not the native authority model.

## Target architecture

~~~text
Human / authenticated session
          |
          v
      Principal
          |
          v
   Capability table
          |
          v
Kernel object handles
          |
  +-------+--------+---------+---------+
  |       |        |         |         |
Process  File    Socket   Secret   IPC Endpoint
  |                                      |
  +------------------+-------------------+
                     |
                 Audit events
                     |
            Policy / verification
                     |
                AI principals
~~~

Every process executes in its own address space and acts as an explicit principal. Access to objects occurs through handles carrying narrowly scoped rights rather than ambient superuser authority.

## 2.1 Process substrate

The current ring-3 bootstrap must become a real process model.

A native process should minimally contain:

~~~text
Process
  pid
  principal_id
  address_space
  kernel_stack
  saved_cpu_context
  handle_table
  resource_limits
  state
~~~

Required runtime work:

- saved CPU contexts;
- context switching between multiple runnable ring-3 processes;
- per-process address spaces;
- kernel stacks per execution context;
- process create/start/exit/kill lifecycle;
- recoverable per-process faults;
- scheduler-visible blocked/runnable states;
- parent/creator attribution where relevant.

A userspace page fault or invalid instruction must terminate or isolate the affected process rather than halt the entire kernel.

## 2.2 Kernel object and handle model

The capability system should be built on explicit kernel objects and per-process handle tables.

Initial object classes:

- Process;
- Thread or execution context;
- File;
- Directory;
- Socket;
- IPC Endpoint;
- Secret;
- Device;
- Shared Memory Region;
- Capability/Grant object where needed by policy services.

Example:

~~~text
Process: service:web

HANDLE   OBJECT              RIGHTS
1        console:stdout      WRITE
7        dir:/srv/web        READ | ENUMERATE
8        socket:tcp/443      LISTEN | ACCEPT
11       secret:tls/site     SIGN
14       ipc:audit           SEND
~~~

Handles must be non-forgeable kernel-managed references. User processes may pass integer handle identifiers, but authority is determined exclusively by the kernel-owned handle table.

## 2.3 Capability security

Capabilities are the native authorization primitive.

A capability binds:

- a principal or process;
- an object;
- a set of rights;
- optional scope constraints;
- optional expiry;
- delegation rules;
- provenance/audit identity.

Required operations:

- grant;
- revoke;
- delegate;
- attenuate;
- inspect;
- expire;
- transfer through controlled IPC.

Rights should be object-specific. Examples include:

~~~text
file.read
file.write
dir.enumerate
socket.connect
socket.listen
process.inspect
process.freeze
secret.sign
secret.derive
ipc.send
ipc.receive
device.use
~~~

A principal cannot create a capability that grants authority it does not already possess or that policy has not independently authorized.

## 2.4 Native identity model

ORYVAEL should represent authority through principals rather than treating a Unix UID as the primary identity.

Initial principal classes:

~~~text
human:<id>
service:<name>
app:<name>
ai:<role>
device:<id>
system:<role>
~~~

Examples:

~~~text
human:administrator
service:ssh
service:network
app:web-server
ai:developer
ai:security
ai:reviewer
~~~

A compatibility UID/GID may be associated with a principal for ported POSIX software, but it must not silently widen authority.

The current `system` and `admin` identities are therefore bootstrap identities, not the final authority architecture.

## 2.5 Sandboxing and resource isolation

ORYVAEL should be sandbox-native rather than depending on a special sandbox application layered on top of the operating system.

A sandbox is a process or process group with deliberately constrained:

- address spaces;
- capability tables;
- IPC endpoints;
- filesystem/object visibility;
- network authority;
- memory limits;
- CPU budgets;
- execution time;
- child-process creation;
- device access.

Example document parser:

~~~text
principal: app:document-parser
allow:
  file.read: input-document
  memory.allocate: bounded
  ipc.send: parser-result

deny-by-absence:
  network.*
  secret.*
  device.*
  process.spawn
~~~

Example developer AI:

~~~text
principal: ai:developer
allow:
  workspace.read: project
  workspace.write: scratch
  tool.execute: compiler
  tool.execute: tests

deny-by-absence:
  production.secret.*
  root.policy.*
  release.root_sign
  audit.delete
~~~

## 2.6 Entropy and cryptographic foundation

Native Phase 2 must remove embedded private development keys from the long-term security model.

The target chain is:

~~~text
hardware / platform entropy
          |
          v
       CSPRNG
          |
          v
     Key Service
          |
   +------+-------+----------------+
   |              |                |
SSH host       machine         artifact /
identity       identity        service keys
~~~

Requirements:

- a kernel or trusted-service random-byte interface backed by suitable entropy;
- CSPRNG state initialization and reseeding policy;
- generated host keys rather than source-embedded private keys;
- key identifiers and metadata;
- non-exportable secret objects where possible;
- rotation and revocation;
- separation between routine service keys and root/constitutional signing keys;
- future integration with TPM/secure element/HSM where hardware permits.

A service should preferably receive a capability such as `secret.sign` rather than raw private-key bytes.

Example:

~~~text
service:ssh
  |
  | CAP_SIGN(secret:ssh-host)
  v
crypto service
  |
  v
signature
~~~

Compromising the SSH service should not automatically reveal reusable host-key material.

## 2.7 Authentication and sessions

Authentication should establish a session bound to a principal rather than merely compare a username string.

Target flow:

~~~text
SSH public key / local login / future passkey
                |
                v
      Authentication Service
                |
                v
          Human Principal
                |
                v
             Session
                |
                v
       Scoped capability set
~~~

A session should carry at least:

- principal identity;
- authentication method;
- credential/key identifier;
- creation time;
- source/transport attribution;
- capability set or capability derivation reference;
- expiry/revocation state.

Root-style unrestricted remote login is not a target requirement.

## 2.8 Attributed audit

Every privileged transition should emit an event that can answer:

- who requested the operation;
- which process/session initiated it;
- which object was targeted;
- which capability authorized or denied it;
- which policy version applied;
- what decision occurred;
- what evidence or resulting artifact was produced.

Conceptual event:

~~~text
principal = service:web
process   = 184
operation = secret.sign
object    = secret:tls/site
capability= handle:11
policy    = native-policy-17
result    = allowed
audit_id  = ...
~~~

Native audit storage should become tamper-evident and eventually durable. AI analyzers may consume audit events but must not be able to rewrite committed audit history.

## 2.9 Native AI supervisor

Only after the previous boundaries exist should an AI runtime be introduced into the native image.

The model is not part of the kernel and is not a privileged oracle.

~~~text
                 ORYVAEL Kernel
                       |
             capability-enforced IPC
                       |
                  AI Supervisor
                       |
       +---------------+----------------+
       |               |                |
  Developer AI    Security AI      Reviewer AI
       |               |                |
       +---------- Tool Broker ----------+
                       |
       filesystem / build / network /
       process / debug / package APIs
~~~

AI workers execute as ordinary ring-3 principals with explicit capability tables.

Example security AI authority:

~~~text
allow:
  audit.read
  process.inspect
  network.telemetry.read
  artifact.read
  finding.create
  action.propose

deny-by-absence:
  root.policy.modify
  capability.self_grant
  audit.delete
  secret.export
  release.root_sign
~~~

High-visibility analysis authority does not imply high-impact mutation authority.

## 2.10 Human-authorized AI interaction

The first native AI workflow should demonstrate the complete authority model rather than only a conversational interface.

Example:

~~~text
oryvael::human> ai analyze system

AI:
  process 84 requested an undeclared outbound connection
  confidence: high
  evidence: audit/...
  recommended action: freeze process 84

Required authority:
  process.freeze:84

Human approval: granted once, expires in 30 seconds

Kernel:
  temporary capability created

AI:
  process 84 frozen
  evidence preserved
  incident record created

Kernel:
  temporary capability revoked
~~~

The same mechanism should support development workflows:

~~~text
human intent
   |
Developer AI
   |
workspace edit
   |
build + tests + security analysis
   |
evidence package
   |
independent verification
   |
deterministic policy
   |
human authorization where required
~~~

The user experience may become conversational, but authorization remains explicit and machine-enforced.

## Native Phase 2 implementation sequence

### 2.1 Process substrate
- multi-process scheduler;
- saved execution contexts;
- process address spaces;
- recoverable process faults.

### 2.2 Object model
- kernel objects;
- process handle tables;
- controlled handle transfer.

### 2.3 Capability enforcement
- object-specific rights;
- grant/revoke/delegate/attenuate;
- deny-by-default enforcement.

### 2.4 Identity
- principal registry;
- human/service/application/AI identities;
- session association.

### 2.5 Sandboxing
- capability confinement;
- resource budgets;
- isolated workspaces;
- process-group lifecycle.

### 2.6 Cryptographic foundation
- entropy;
- CSPRNG;
- key generation;
- secret objects;
- host/machine identity.

### 2.7 Authentication
- key-based human authentication;
- authenticated session objects;
- capability derivation for sessions.

### 2.8 Audit
- native attributed event stream;
- tamper-evident chaining;
- durable persistence when storage is available.

### 2.9 AI supervisor
- ring-3 AI principal;
- capability-aware tool broker;
- policy-controlled system APIs.

### 2.10 First governed native AI workflow
- inspect runtime state;
- analyze code/evidence;
- detect a security issue;
- propose an action;
- obtain scoped authorization;
- execute through a temporary capability;
- record immutable evidence.

## Exit criteria

Native Phase 2 is complete when all of the following are demonstrated in one bootable image:

1. at least two independent ring-3 processes are context-switched by the native scheduler;
2. one process can fault without terminating the kernel or unrelated processes;
3. processes access kernel objects only through kernel-managed handles;
4. attempts to use absent or revoked capabilities fail closed;
5. authenticated human sessions resolve to explicit principals;
6. private SSH/machine key material is generated/provisioned outside source code;
7. a service can use a non-exportable or non-directly-exposed signing capability;
8. privileged operations produce attributed audit events;
9. an AI worker executes as a restricted ring-3 principal;
10. the AI can analyze system state and request an action but cannot self-grant that action;
11. a human or deterministic policy can issue a scoped, temporary capability;
12. the executed action and resulting evidence are auditable.

At that point ORYVAEL stops being only a native-kernel proof and becomes a governed application and intelligence substrate.