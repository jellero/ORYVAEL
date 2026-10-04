# Docker Base System

This image packages the current ORYVAEL Linux-first trusted-core reference as a runnable development system. It is not a bootable OS image and it is not a production security boundary.

The container starts the trusted supervisor service, persists its root policy and audit state, and includes a signed development principal plus a sandbox demo job.

## Start

Requirements:

- Docker Engine with Compose v2;
- a Linux host, or Docker Desktop with a Linux VM;
- permission for the container to create nested namespaces.

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

## Why the extra Docker permissions exist

The supervisor builds its sandbox with `unshare`, Bubblewrap and resource limits. Docker's default seccomp/AppArmor policy normally blocks part of that nested namespace/mount sequence.

The development Compose profile therefore adds `SYS_ADMIN` and disables the container seccomp/AppArmor profiles. This is a broad host-facing permission and must not be treated as the final ORYVAEL deployment model.

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
