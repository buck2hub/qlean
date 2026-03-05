#!/usr/bin/env bash
set -euo pipefail

# Qlean host prerequisites helper.
#
# This script is intentionally conservative: it configures QEMU bridge-helper
# permissions for the Qlean bridge and applies the minimal capabilities needed
# for qemu-bridge-helper.
#
# It does *not* create the bridge or manage network state (that remains the
# responsibility of Qlean at runtime).

BRIDGE_NAME="${QLEAN_BRIDGE_NAME:-qlbr0}"

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: Please run as root (e.g. sudo $0)" >&2
    exit 1
  fi
}

ensure_bridge_conf() {
  mkdir -p /etc/qemu
  local conf=/etc/qemu/bridge.conf

  if [[ -f "$conf" ]]; then
    if grep -qE "^allow[[:space:]]+all$" "$conf"; then
      echo "OK: $conf already allows all bridges"
      chmod 0644 "$conf"
      return
    fi
    if grep -qE "^allow[[:space:]]+${BRIDGE_NAME}$" "$conf"; then
      echo "OK: $conf already allows ${BRIDGE_NAME}"
      chmod 0644 "$conf"
      return
    fi
  fi

  echo "allow ${BRIDGE_NAME}" >> "$conf"
  chmod 0644 "$conf"
  echo "Wrote: allow ${BRIDGE_NAME} -> $conf"
}

find_qemu_bridge_helper() {
  # Common distro paths.
  local candidates=(
    /usr/lib/qemu/qemu-bridge-helper
    /usr/libexec/qemu-bridge-helper
    /usr/lib64/qemu/qemu-bridge-helper
  )

  for p in "${candidates[@]}"; do
    if [[ -x "$p" ]]; then
      echo "$p"
      return 0
    fi
  done

  # Fall back to PATH.
  if command -v qemu-bridge-helper >/dev/null 2>&1; then
    command -v qemu-bridge-helper
    return 0
  fi

  return 1
}

ensure_bridge_helper_caps() {
  local helper
  if ! helper="$(find_qemu_bridge_helper)"; then
    echo "WARN: qemu-bridge-helper not found. Install QEMU first." >&2
    return
  fi

  if command -v setcap >/dev/null 2>&1; then
    # Prefer file capabilities over setuid.
    chmod u-s "$helper" || true
    setcap cap_net_admin+ep "$helper"

    echo "OK: setcap cap_net_admin+ep $helper"
    if command -v getcap >/dev/null 2>&1; then
      getcap "$helper" || true
    fi
  else
    echo "WARN: setcap not found. On Debian/Ubuntu install libcap2-bin." >&2
  fi
}

maybe_install_guestfs_tools_ubuntu() {
  # Only attempt package installation on Debian/Ubuntu when apt-get is available.
  if ! command -v apt-get >/dev/null 2>&1; then
    return
  fi

  # guestfish/virt-copy-out are used for kernel/initrd extraction.
  if command -v guestfish >/dev/null 2>&1 && command -v virt-copy-out >/dev/null 2>&1; then
    echo "OK: libguestfs tools already installed"
    return
  fi

  echo "INFO: Installing libguestfs tools (guestfish, virt-copy-out) via apt-get"
  apt-get update -y
  apt-get install -y libguestfs-tools
}

need_root
ensure_bridge_conf
ensure_bridge_helper_caps
maybe_install_guestfs_tools_ubuntu

echo "DONE"
