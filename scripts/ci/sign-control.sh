#!/usr/bin/env bash
set -euo pipefail

kind="${1:?control kind required}"
artifact="${2:?artifact path required}"
cli="${ORYVAEL_CLI:-./target/debug/oryvael}"
key="${ORYVAEL_CONTROL_TEST_KEY:-/tmp/oryvael-control-root/root-v2.key}"

"$cli" control-sign \
    --private-key "$key" \
    --signer-id governance/ci \
    --key-version 2 \
    --kind "$kind" \
    --artifact "$artifact" \
    > "$artifact.control.json"
