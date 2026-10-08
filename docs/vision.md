# ORYVAEL Vision

## Problem

Existing operating systems assume human-authored applications and human-operated administration. AI agents can generate code and operate files, networks, CI, deployment infrastructure and physical devices faster than traditional review processes can absorb.

Treating such an agent as an ordinary administrator concentrates too much authority. Treating an AI-controlled IoT or robotic device as a passive peripheral has the same problem when the agent can directly operate actuators, field buses or safety-relevant hardware.

## Objective

Build an OS architecture where AI can perform most software-engineering and operational work while humans retain control over:
- architectural intent;
- constitutional constraints;
- acceptable risk;
- root trust;
- critical release authority;
- privacy boundaries;
- physical-world actuation authority;
- irreversible actions.

## Desired properties

**Evolvable:** features, fixes and optimization without uncontrolled legacy.

**Explainable:** privileged behavior traceable from requirement to deployment or physical action.

**Constrained:** explicit capabilities; absence of grant means denial.

**Observable:** structured metrics, logs, traces and audit.

**Reversible:** atomic updates and known-good rollback where the target hardware permits it.

**Reproducible:** release reconstruction from source, toolchain, dependencies and build recipe.

**Cross-device:** Desktop, Mobile and Embedded/Edge profiles share identity, capability, update and audit contracts while adapting isolation and runtime mechanisms to the hardware class.

**Physical-authority aware:** remote AI intent is never equivalent to direct actuator authority; device-side deterministic policy remains the enforcement point.

## Product scope

ORYVAEL spans three related runtime profiles:
- **Desktop** for workstations and general-purpose systems;
- **Mobile** for phones and portable ARM64 devices;
- **Embedded / Edge** for IoT, robotics, gateways and constrained physical-world controllers.

The profiles may expose different user interfaces, scheduling models and hardware abstractions, but they must preserve the same principle: intelligence can request or propose actions, while deterministic authority is independently enforced.

## Non-goals

ORYVAEL does not aim to put an LLM in the scheduler, allow natural language to bypass policy, trust model self-evaluation as proof, replace deterministic authorization with probabilistic judgment, create one omnipotent system agent, or require an AI model to execute locally on every device.

The user may delegate work; delegation does not silently transfer ownership of authority. A remote AI agent may request a physical action; that request does not silently become hardware authority.
