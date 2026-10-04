#!/bin/sh
set -eu

STATE_DIR="${ORYVAEL_STATE_DIR:-/var/lib/oryvael}"
SOCKET_PATH="${ORYVAEL_SOCKET:-/run/oryvael/trusted.sock}"
CONTROL_DIR="$STATE_DIR/control"
AUDIT_DIR="$STATE_DIR/audit"
BOOTSTRAP_DIR="$STATE_DIR/bootstrap"
ROOT_KEY="$CONTROL_DIR/root.key"
ROOT_POLICY="$CONTROL_DIR/root-policy.json"
MIN_EPOCH="$CONTROL_DIR/root-policy.min-epoch"
PEER_POLICY="$CONTROL_DIR/peer-policy.json"
SERVICE_AUDIT="$AUDIT_DIR/trusted-service.jsonl"
BOOTSTRAP_PRINCIPAL="$BOOTSTRAP_DIR/developer-principal.json"
BOOTSTRAP_JOB="$BOOTSTRAP_DIR/demo-job.json"

mkdir -p "$CONTROL_DIR" "$AUDIT_DIR" "$BOOTSTRAP_DIR" /run/oryvael /workspace

if { [ -f "$ROOT_KEY" ] && [ ! -f "$ROOT_POLICY" ]; } || \
   { [ ! -f "$ROOT_KEY" ] && [ -f "$ROOT_POLICY" ]; }; then
    echo "ORYVAEL Docker state is inconsistent: root.key and root-policy.json must exist together" >&2
    exit 1
fi

if [ ! -f "$ROOT_KEY" ]; then
    umask 077
    openssl rand -hex 32 > "$ROOT_KEY"
    public_key="$(oryvael control-public-key --private-key "$ROOT_KEY")"

    umask 022
    cat > "$ROOT_POLICY" <<EOF
{
  "version": 1,
  "epoch": 1,
  "signers": [
    {
      "id": "governance/docker-dev",
      "key_version": 1,
      "public_key_hex": "$public_key",
      "status": "active",
      "allowed_kinds": [
        "tool_catalog",
        "change_plan",
        "principal_policy",
        "workspace_registry",
        "peer_policy"
      ]
    }
  ]
}
EOF
    chmod 0600 "$ROOT_KEY"
    chmod 0644 "$ROOT_POLICY"
fi

if [ ! -f "$MIN_EPOCH" ]; then
    epoch="$(python3 - "$ROOT_POLICY" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["epoch"])
PY
)"
    printf '%s\n' "$epoch" > "$MIN_EPOCH"
    chmod 0644 "$MIN_EPOCH"
fi

export ORYVAEL_ROOT_POLICY="$ROOT_POLICY"
export ORYVAEL_ROOT_POLICY_MIN_EPOCH="$(tr -d '[:space:]' < "$MIN_EPOCH")"

install -m 0644 /opt/oryvael/examples/supervisor/developer-principal.json "$BOOTSTRAP_PRINCIPAL"
install -m 0644 /opt/oryvael/docker/demo-job.json "$BOOTSTRAP_JOB"

signature_tmp="$BOOTSTRAP_PRINCIPAL.control.json.tmp"
oryvael control-sign \
    --private-key "$ROOT_KEY" \
    --signer-id governance/docker-dev \
    --key-version 1 \
    --kind principal_policy \
    --artifact "$BOOTSTRAP_PRINCIPAL" \
    > "$signature_tmp"
mv "$signature_tmp" "$BOOTSTRAP_PRINCIPAL.control.json"
chmod 0644 "$BOOTSTRAP_PRINCIPAL.control.json"

oryvael control-verify \
    --root-policy "$ROOT_POLICY" \
    --kind principal_policy \
    --artifact "$BOOTSTRAP_PRINCIPAL" \
    >/dev/null

service_sha256="$(sha256sum /usr/local/bin/oryvael-service | awk '{print $1}')"
cat > "$PEER_POLICY" <<EOF
{
  "version": 1,
  "bindings": [
    {
      "id": "docker-dev-service-client",
      "uid": 0,
      "gid": 0,
      "executable_sha256": "$service_sha256",
      "operations": ["status", "verify", "supervise"],
      "principals": ["developer-ai/demo"]
    }
  ]
}
EOF
chmod 0644 "$PEER_POLICY"

peer_signature_tmp="$PEER_POLICY.control.json.tmp"
oryvael control-sign \
    --private-key "$ROOT_KEY" \
    --signer-id governance/docker-dev \
    --key-version 1 \
    --kind peer_policy \
    --artifact "$PEER_POLICY" \
    > "$peer_signature_tmp"
mv "$peer_signature_tmp" "$PEER_POLICY.control.json"
chmod 0644 "$PEER_POLICY.control.json"

oryvael control-verify \
    --root-policy "$ROOT_POLICY" \
    --kind peer_policy \
    --artifact "$PEER_POLICY" \
    >/dev/null

case "${1:-serve}" in
    serve)
        if [ "$#" -gt 0 ]; then
            shift
        fi
        exec oryvael-service serve \
            --socket "$SOCKET_PATH" \
            --root-policy "$ROOT_POLICY" \
            --minimum-epoch "$MIN_EPOCH" \
            --peer-policy "$PEER_POLICY" \
            --audit "$SERVICE_AUDIT" \
            "$@"
        ;;
    shell)
        exec /bin/sh
        ;;
    *)
        exec "$@"
        ;;
esac
