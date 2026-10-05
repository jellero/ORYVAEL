#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/oryvael-os}"
DIST_DIR="${ORYVAEL_DIST_DIR:-$ROOT/dist}"
IMAGE="$DIST_DIR/oryvael-x86_64-uefi.img"

for tool in cargo rustup dd mcopy; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing host build tool: $tool" >&2
    exit 2
  fi
done

if command -v mkfs.vfat >/dev/null 2>&1; then
  MKFS_FAT="$(command -v mkfs.vfat)"
elif command -v mkfs.fat >/dev/null 2>&1; then
  MKFS_FAT="$(command -v mkfs.fat)"
else
  echo "missing host build tool: mkfs.vfat or mkfs.fat (install dosfstools)" >&2
  exit 2
fi

ADMIN_KEY="${ORYVAEL_ADMIN_PUBKEY_FILE:-}"
if [[ -z "$ADMIN_KEY" && -f "$ROOT/.oryvael/oryvael_admin.pub" ]]; then
  ADMIN_KEY="$ROOT/.oryvael/oryvael_admin.pub"
fi
if [[ -n "$ADMIN_KEY" ]]; then
  if [[ ! -f "$ADMIN_KEY" ]]; then
    echo "ORYVAEL admin public key not found: $ADMIN_KEY" >&2
    exit 2
  fi
  ADMIN_KEY_DIR="$(cd "$(dirname "$ADMIN_KEY")" && pwd)"
  export ORYVAEL_ADMIN_PUBKEY_FILE="$ADMIN_KEY_DIR/$(basename "$ADMIN_KEY")"
  printf 'ORYVAEL admin public key: %s\n' "$ORYVAEL_ADMIN_PUBKEY_FILE"
else
  echo "warning: no local ORYVAEL admin key found; using the built-in development public key" >&2
fi

rustup target add x86_64-unknown-uefi >/dev/null

CARGO_TARGET_DIR="$TARGET_DIR" \
  cargo build \
    --manifest-path "$ROOT/kernel/Cargo.toml" \
    --target x86_64-unknown-uefi \
    --release

KERNEL_EFI="$TARGET_DIR/x86_64-unknown-uefi/release/oryvael-kernel.efi"
if [[ ! -f "$KERNEL_EFI" ]]; then
  echo "kernel EFI image not found: $KERNEL_EFI" >&2
  exit 3
fi

mkdir -p "$DIST_DIR"
rm -f "$IMAGE"
dd if=/dev/zero of="$IMAGE" bs=1048576 count=64 2>/dev/null
"$MKFS_FAT" -F 32 -n ORYVAEL "$IMAGE" >/dev/null

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
mkdir -p "$STAGING/EFI/BOOT"
cp "$KERNEL_EFI" "$STAGING/EFI/BOOT/BOOTX64.EFI"
mcopy -s -i "$IMAGE" "$STAGING/EFI" ::/

cp "$KERNEL_EFI" "$DIST_DIR/BOOTX64.EFI"

printf 'ORYVAEL bare-metal image: %s\n' "$IMAGE"
printf 'Kernel EFI payload:       %s\n' "$DIST_DIR/BOOTX64.EFI"
