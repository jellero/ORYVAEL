# Desktop and Mobile Profiles

## Shared security contract

Both profiles share:
- identity;
- capability semantics;
- app manifest;
- AI agent isolation;
- policy engine;
- audit format;
- artifact provenance;
- update verification;
- developer change plans.

## Desktop

Focus:
- multitasking/window management;
- terminal and developer tools;
- local services/containers;
- high-performance GPU;
- filesystem-heavy workflows;
- optional professional elevated capabilities.

Desktop power must not reintroduce ambient authority.

## Mobile

Focus:
- battery/thermal limits;
- cellular stack;
- camera/microphone/sensors;
- background execution budgets;
- user-presence requirements;
- secure element;
- stricter default lifecycle.

## Continuity

Cross-device continuation transfers application state, not authority.

Moving a session from phone to PC does not automatically grant phone capabilities on the destination. The destination independently resolves its effective grants.

## Presentation

One application may declare Desktop and Mobile presentation profiles while preserving one security manifest and one application identity.
