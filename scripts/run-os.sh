#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=""
GUI=0
SSH_HOST_PORT="${ORYVAEL_SSH_HOST_PORT:-2222}"

usage() {
  cat <<'EOF'
Usage: ./scripts/run-os.sh [--gui] [--ssh-port PORT] [image]

  --gui             keep the emulated VGA/GOP display visible
  --headless        suppress the host display window (default)
  --ssh-port PORT   host TCP port forwarded to guest tcp/22 (default 2222)
  image             optional path to a raw ORYVAEL UEFI disk image

Networking uses QEMU user-mode NAT. By default:
  host 127.0.0.1:2222 -> guest tcp/22
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gui)
      GUI=1
      ;;
    --headless)
      GUI=0
      ;;
    --ssh-port)
      shift
      if [[ $# -eq 0 ]]; then
        echo "--ssh-port requires a value" >&2
        exit 2
      fi
      SSH_HOST_PORT="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$IMAGE" ]]; then
        echo "only one image path may be supplied" >&2
        exit 2
      fi
      IMAGE="$1"
      ;;
  esac
  shift
done

if ! [[ "$SSH_HOST_PORT" =~ ^[0-9]+$ ]] || (( SSH_HOST_PORT < 1 || SSH_HOST_PORT > 65535 )); then
  echo "invalid SSH host port: $SSH_HOST_PORT" >&2
  exit 2
fi

IMAGE="${IMAGE:-$ROOT/dist/oryvael-x86_64-uefi.img}"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  echo "qemu-system-x86_64 is required on the host" >&2
  exit 2
fi

if [[ ! -f "$IMAGE" ]]; then
  echo "boot image not found: $IMAGE" >&2
  echo "run scripts/build-os.sh first" >&2
  exit 2
fi

find_firmware() {
  local candidate
  for candidate in "$@"; do
    if [[ -n "$candidate" && -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

BREW_QEMU_SHARE=""
if command -v brew >/dev/null 2>&1; then
  BREW_QEMU_PREFIX="$(brew --prefix qemu 2>/dev/null || true)"
  if [[ -n "$BREW_QEMU_PREFIX" ]]; then
    BREW_QEMU_SHARE="$BREW_QEMU_PREFIX/share/qemu"
  fi
fi

OVMF_CODE="${OVMF_CODE:-$(find_firmware \
  /usr/share/OVMF/OVMF_CODE_4M.fd \
  /usr/share/OVMF/OVMF_CODE.fd \
  /usr/share/edk2/x64/OVMF_CODE.fd \
  /usr/share/edk2-ovmf/x64/OVMF_CODE.fd \
  /usr/share/qemu/edk2-x86_64-code.fd \
  "$BREW_QEMU_SHARE/edk2-x86_64-code.fd" \
  || true)}"
OVMF_VARS="${OVMF_VARS:-$(find_firmware \
  /usr/share/OVMF/OVMF_VARS_4M.fd \
  /usr/share/OVMF/OVMF_VARS.fd \
  /usr/share/edk2/x64/OVMF_VARS.fd \
  /usr/share/edk2-ovmf/x64/OVMF_VARS.fd \
  /usr/share/qemu/edk2-i386-vars.fd \
  "$BREW_QEMU_SHARE/edk2-i386-vars.fd" \
  || true)}"

if [[ -z "$OVMF_CODE" || -z "$OVMF_VARS" ]]; then
  echo "OVMF/EDK2 firmware files not found; set OVMF_CODE and OVMF_VARS" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
cp "$OVMF_VARS" "$TMP_DIR/OVMF_VARS.fd"

QEMU_ARGS=(
  -machine q35
  -cpu qemu64
  -m 256M
  -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
  -drive "if=pflash,format=raw,file=$TMP_DIR/OVMF_VARS.fd"
  -drive "if=virtio,format=raw,file=$IMAGE"
  -serial stdio
  -monitor none
  -device rtl8139,netdev=net0
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_HOST_PORT}-:22"
)

if [[ "$GUI" -eq 0 ]]; then
  QEMU_ARGS+=( -display none )
fi

printf 'ORYVAEL QEMU NAT: 127.0.0.1:%s -> guest tcp/22\n' "$SSH_HOST_PORT"
printf 'ORYVAEL image:    %s\n' "$IMAGE"
if [[ "$GUI" -eq 1 ]]; then
  echo "ORYVAEL display:  GUI enabled"
else
  echo "ORYVAEL display:  headless (use --gui to show GOP graphics)"
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
