# Capability Security Model

## Goal

Replace broad ambient administrator semantics with explicit grants defining who may do what, to which target, under which constraints.

## Logical capability

~~~
principal
resource
action
scope
constraints
delegation
expiry
~~~

Example:

~~~
principal: developer-ai/42
resource: source
action: write
scope: /workspace/change-918/**
constraints:
  network: denied
  production: denied
~~~

## Evaluation

1. Authenticate principal.
2. Normalize requested operation.
3. Collect effective grants.
4. Evaluate explicit denies.
5. Evaluate matching allows.
6. Apply temporal/context constraints.
7. Emit decision and audit correlation ID.
8. Only then invoke the broker.

Explicit deny wins. No matching allow means deny.

## Scope forms

Scopes are structural rather than natural language:
- filesystem prefix;
- repository/branch;
- API method;
- network domain;
- device identifier;
- database/schema;
- artifact namespace.

## Capability acquisition

Capabilities come from:
- static role policy;
- approved change plan;
- explicit user consent;
- bounded delegation.

An AI principal cannot create its own grant.

## High-risk capabilities

Examples:
- production.write;
- release.sign;
- policy.write;
- identity.admin;
- secrets.export;
- kernel.modify;
- updater.modify;
- audit.admin;
- architecture.constitutional.

## Delegation

A delegated grant:
- cannot exceed the delegator's effective grant;
- carries the delegator identity;
- has an explicit scope;
- should have an expiry;
- is revocable.

## End-user applications

The same abstraction applies to apps:
- camera.capture while foreground;
- filesystem.read ~/Pictures;
- network.connect api.example.com;
- notifications.send.

The effective set must be inspectable and revocable by the user or authorized administrator.
