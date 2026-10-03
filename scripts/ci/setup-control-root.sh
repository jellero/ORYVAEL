#!/usr/bin/env bash
set -euo pipefail

CLI="${1:-./target/debug/oryvael}"
ROOT_DIR=/tmp/oryvael-control-root
ROOT_POLICY=/etc/oryvael/root-policy.json
MIN_EPOCH=/etc/oryvael/root-policy.min-epoch
OLD_KEY="$ROOT_DIR/root-v1.key"
ACTIVE_KEY="$ROOT_DIR/root-v2.key"

rm -rf "$ROOT_DIR"
mkdir -p "$ROOT_DIR"
openssl rand -hex 32 > "$OLD_KEY"
openssl rand -hex 32 > "$ACTIVE_KEY"

old_public="$($CLI control-public-key --private-key "$OLD_KEY")"
active_public="$($CLI control-public-key --private-key "$ACTIVE_KEY")"

python - "$old_public" "$active_public" "$ROOT_DIR/root-policy.json" <<'PY'
import json
import sys

old_public, active_public, output = sys.argv[1:]
kinds = ["tool_catalog", "change_plan", "principal_policy", "workspace_registry"]
policy = {
    "version": 1,
    "epoch": 2,
    "signers": [
        {
            "id": "governance/ci",
            "key_version": 1,
            "public_key_hex": old_public.strip(),
            "status": "revoked",
            "allowed_kinds": kinds,
        },
        {
            "id": "governance/ci",
            "key_version": 2,
            "public_key_hex": active_public.strip(),
            "status": "active",
            "allowed_kinds": kinds,
        },
    ],
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(policy, handle, indent=2)
    handle.write("\n")
PY

sudo mkdir -p /etc/oryvael
sudo install -m 0644 "$ROOT_DIR/root-policy.json" "$ROOT_POLICY"
printf '2\n' | sudo tee "$MIN_EPOCH" >/dev/null

if [[ -n "${GITHUB_ENV:-}" ]]; then
    {
        echo "ORYVAEL_ROOT_POLICY=$ROOT_POLICY"
        echo "ORYVAEL_ROOT_POLICY_MIN_EPOCH=2"
        echo "ORYVAEL_CONTROL_TEST_KEY=$ACTIVE_KEY"
    } >> "$GITHUB_ENV"
fi

sign() {
    local kind="$1"
    local artifact="$2"
    "$CLI" control-sign \
        --private-key "$ACTIVE_KEY" \
        --signer-id governance/ci \
        --key-version 2 \
        --kind "$kind" \
        --artifact "$artifact" \
        > "$artifact.control.json"
}

while IFS= read -r -d '' file; do
    sign principal_policy "$file"
done < <(find examples -type f -name '*principal.json' -print0)

while IFS= read -r -d '' file; do
    sign change_plan "$file"
done < <(find examples -type f -name '*plan.json' -print0)

sign workspace_registry examples/workspace/registry.json
sign tool_catalog examples/tool-broker/catalog.json

# Rotation/revocation smoke: an artifact signed by the retired key must be rejected.
cp examples/build/c1-plan.json "$ROOT_DIR/revoked-plan.json"
"$CLI" control-sign \
    --private-key "$OLD_KEY" \
    --signer-id governance/ci \
    --key-version 1 \
    --kind change_plan \
    --artifact "$ROOT_DIR/revoked-plan.json" \
    > "$ROOT_DIR/revoked-plan.json.control.json"

set +e
"$CLI" control-verify \
    --root-policy "$ROOT_POLICY" \
    --kind change_plan \
    --artifact "$ROOT_DIR/revoked-plan.json" \
    >/tmp/oryvael-revoked-control.out 2>/tmp/oryvael-revoked-control.err
status=$?
set -e
test "$status" -ne 0
cat /tmp/oryvael-revoked-control.err
