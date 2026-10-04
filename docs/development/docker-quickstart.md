# Docker Base System

This image packages the current ORYVAEL Linux-first trusted-core reference as a runnable development system. It is not a bootable OS image and it is not a production security boundary.

The container starts the trusted supervisor service, persists its root policy and audit state, and includes a signed development principal plus a sandbox demo job.

## Start

Requirements:

- Docker Engine with Compose v2;
- a Linux host, or Docker Desktop with a Linux VM;
- permission to run the ORYVAEL development container in privileged mode so the supervisor can create its nested namespace and mount sandbox.

Run:

```sh
docker compose up -d --build
```

Check the trusted service:

```sh
docker compose exec oryvael \
  oryvael-service status --socket /run/oryvael/trusted.sock
```

Check sandbox support:

```sh
docker compose exec oryvael oryvael supervisor-doctor
```

`ready_for_basic_sandbox` should be `true` before using the confinement demo.

## Run the confinement demo

```sh
docker compose exec oryvael \
  oryvael-service supervise \
  --socket /run/oryvael/trusted.sock \
  --principal /var/lib/oryvael/bootstrap/developer-principal.json \
  --job /var/lib/oryvael/bootstrap/demo-job.json
```

The job writes:

```text
/workspace/demo/generated.txt
```

Verify the job audit chain:

```sh
docker compose exec oryvael \
  oryvael audit-verify /var/lib/oryvael/demo/audit.jsonl
```

Inspect the trusted-service audit:

```sh
docker compose exec oryvael \
  oryvael audit-verify /var/lib/oryvael/audit/trusted-service.jsonl
```

## Persistent state

Compose creates two named volumes:

- `oryvael-state` at `/var/lib/oryvael` for the development root key, root policy, minimum epoch, service audit and artifacts;
- `oryvael-workspace` at `/workspace` for sandbox workspaces.

The entrypoint creates the development root only when the state volume is empty. If `root.key` and `root-policy.json` become inconsistent, startup fails closed instead of replacing one side silently.

Reset all Docker development authority and state with:

```sh
docker compose down -v
```

The next startup creates a new development root key and root policy.

## Why privileged mode is required here

The current supervisor builds its sandbox with `unshare`, Bubblewrap, a new PID namespace, a fresh `/proc` mount and resource limits. A normal Docker container, including one with only `SYS_ADMIN`, can still reject Bubblewrap's nested `/proc` mount with `Operation not permitted`.

The development Compose profile therefore uses `privileged: true`. This gives the outer container broad host-facing authority and must not be treated as the final ORYVAEL deployment model. ORYVAEL's inner Bubblewrap sandbox still applies to the supervised job, but the outer Docker container itself is privileged.

The container deliberately does **not** mount `/var/run/docker.sock` and does not delegate Docker daemon authority to the supervised workload.

For a production design, the trusted supervisor should run in a dedicated host service or VM boundary with narrowly defined namespace/mount authority rather than in this development container profile.

## Run a one-off command

The entrypoint also accepts arbitrary commands:

```sh
docker compose run --rm oryvael oryvael --help
```

Open a shell:

```sh
docker compose run --rm oryvael shell
```
