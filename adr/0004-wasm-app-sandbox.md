# ADR-0004: WASM as a preferred portable sandbox

Status: Proposed

WebAssembly/WASI-style workloads are a preferred target for AI-generated utilities because host access can be narrow and portable.

WASM is not mandatory for GPU-heavy native apps, kernel-adjacent services or compatibility workloads.

All runtimes must map privileged access to the same ORYVAEL capability model.

Acceptance requires benchmarks for startup, IPC, filesystem broker overhead, graphics integration, debugging and mobile energy impact.
