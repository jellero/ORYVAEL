# Git Workspace Broker

## Purpose

The Workspace Broker provisions development worktrees without allowing an AI principal to choose arbitrary host paths or arbitrary branch names.

A request contains only:
- principal identity;
- change ID;
- change-plan path;
- logical repository ID;
- base ref;
- external audit path.

Repository path and workspace root come from an administrator-controlled registry.

## Generated state

For a registry entry:

    id: oryvael-demo
    path: /srv/oryvael/repos/ORYVAEL
    workspace_root: /srv/oryvael/workspaces

and change ID:

    CHG-123

the broker derives:

    workspace: /srv/oryvael/workspaces/CHG-123
    branch: oryvael/CHG-123

The caller cannot replace either value.

Change IDs are restricted to ASCII letters, digits, dot, underscore and dash before they participate in path or ref construction. The resulting branch is additionally checked with Git check-ref-format.

## Three-way authorization

Provisioning succeeds only when all three layers agree.

The change plan must request:
- repository:<repository-id>:read
- workspace:provision
- git:branch:create

The principal policy must independently permit:
- repository.read for the logical repository ID;
- workspace.provision for the generated workspace path;
- git_branch.create for the generated branch.

The registry determines which physical repository and workspace root correspond to the logical repository ID.

Changing only the request or only the change plan therefore cannot create authority.

## Base ref handling

The base ref is resolved with:

    git rev-parse --verify --end-of-options <base>^{commit}

The broker then passes the resulting hexadecimal commit ID to git worktree add.

This removes option injection from the actual worktree command and records the resolved base commit in the result and audit event.

## Transaction behavior

Before mutation the broker checks:
- target workspace does not already exist;
- generated branch does not already exist;
- all control inputs are outside the generated workspace;
- audit path is outside the generated workspace;
- policy decisions pass.

Git then creates the branch and worktree in one operation.

If Git reports failure, the broker attempts to remove any partial worktree and generated branch before returning the error.

## Audit

The shared tamper-evident JSONL journal records:
- request hashes for principal, registry, request and change plan;
- logical repository ID;
- generated branch;
- repository.read decision;
- workspace.provision decision;
- git_branch.create decision;
- final base commit and workspace result.

Every event for the operation shares one operation ID.

## Security boundary

This broker provisions local workspaces only. It does not perform fetch, push, merge or release publication.

Networked Git operations will be separate named capabilities because reading a local repository and communicating with a remote repository have different security impact.
