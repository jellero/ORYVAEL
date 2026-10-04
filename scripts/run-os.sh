#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-$ROOT/dist/oryvael-x86_64-uefi.img}"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "qemu-system-x86_64 is required on the host" >&2
  exit 2
fi

if [[ ! -f "$IMAGE" ]]; then
  echo "boot image not found: $IMAGE" >&2
  echo "run scripts/build-os.sh first" >&2
  exit 2
fi

find_ovmf() {
  local name="$1"
  local candidate
  for candidate in \
    "/usr/share/OVMF/$name" \
    "/usr/share/edk2/x64/$name" \
    "/usr/share/edk2-ovmf/x64/$name"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

OVMF_CODE="${OVMF_CODE:-$(find_ovmf OVMF_CODE.fd || true)}"
OVMF_VARS="${OVMF_VARS:-$(find_ovmf OVMF_VARS.fd || true)}"

if [[ -z "$OVMF_CODE" || -z "$OVMF_VARS" ]]; then
  echo "OVMF firmware files not found; set OVMF_CODE and OVMF_VARS" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
cp "$OVMF_VARS" "$TMP_DIR/OVMF_VARS.fd"

exec qemu-system-x86_64 \
  -machine q35 \
  -cpu qemu64 \
  -m 256M \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$TMP_DIR/OVMF_VARS.fd" \
  -drive if=virtio,format=raw,file="$IMAGE" \
  -display none \
  -serial stdio \
  -monitor none \
  -net none \
  -no-reboot
