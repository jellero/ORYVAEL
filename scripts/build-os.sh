#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/oryvael-os}"
DIST_DIR="${ORYVAEL_DIST_DIR:-$ROOT/dist}"
IMAGE="$DIST_DIR/oryvael-x86_64-uefi.img"

for tool in cargo rustup mkfs.vfat mmd mcopy truncate; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing host build tool: $tool" >&2
    exit 2
  fi
done

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
truncate -s 64M "$IMAGE"
mkfs.vfat -F 32 -n ORYVAEL "$IMAGE" >/dev/null
mmd -i "$IMAGE" ::/EFI
mmd -i "$IMAGE" ::/EFI/BOOT
mcopy -i "$IMAGE" "$KERNEL_EFI" ::/EFI/BOOT/BOOTX64.EFI

cp "$KERNEL_EFI" "$DIST_DIR/BOOTX64.EFI"

printf 'ORYVAEL bare-metal image: %s\n' "$IMAGE"
printf 'Kernel EFI payload:       %s\n' "$DIST_DIR/BOOTX64.EFI"
