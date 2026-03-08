#!/usr/bin/env bash
set -euo pipefail

# Qlean host prerequisites helper.
#
# This script configures the explicit host prerequisites required by Qlean:
#   - qemu-bridge-helper permissions for the Qlean bridge
#   - the libvirt 'qlean' network and qlbr0 bridge
#   - host libguestfs-tools installation/runtime verification
#
# Qlean no longer provisions or discovers fallback paths at runtime; run this
# script once before using distro image creation or E2E tests.

BRIDGE_NAME="${QLEAN_BRIDGE_NAME:-qlbr0}"
VIRSH_URI="qemu:///system"

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

ensure_qlean_network() {
  if ! command -v virsh >/dev/null 2>&1; then
    echo "ERROR: virsh not found. Install libvirt-clients/libvirt-daemon-system first." >&2
    exit 1
  fi

  if ! virsh -c "$VIRSH_URI" net-info qlean >/dev/null 2>&1; then
    local xml
    xml=$(mktemp)
    cat > "$xml" <<EOF
<network>
  <name>qlean</name>
  <bridge name='${BRIDGE_NAME}'/>
  <forward mode='nat'/>
  <ip address='192.168.221.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.221.2' end='192.168.221.254'/>
    </dhcp>
  </ip>
</network>
EOF
    echo "INFO: defining libvirt network qlean"
    virsh -c "$VIRSH_URI" net-define "$xml"
    rm -f "$xml"
  else
    echo "OK: libvirt network qlean already defined"
  fi

  echo "INFO: ensuring libvirt network qlean is active"
  virsh -c "$VIRSH_URI" net-start qlean >/dev/null 2>&1 || true
  virsh -c "$VIRSH_URI" net-autostart qlean >/dev/null 2>&1 || true
}

maybe_install_guestfs_tools_ubuntu() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return
  fi

  if command -v guestfish >/dev/null 2>&1 \
    && command -v virt-copy-out >/dev/null 2>&1 \
    && command -v libguestfs-test-tool >/dev/null 2>&1; then
    echo "OK: libguestfs tools already installed"
    return
  fi

  echo "INFO: Installing libguestfs tools (guestfish, virt-copy-out) via apt-get"
  apt-get update -y
  apt-get install -y libguestfs-tools
}

verify_guestfs_runtime() {
  if ! command -v libguestfs-test-tool >/dev/null 2>&1; then
    echo "WARN: libguestfs-test-tool not found after installation. Check your libguestfs-tools package." >&2
    return
  fi

  echo "INFO: Verifying host libguestfs runtime (LIBGUESTFS_BACKEND=direct libguestfs-test-tool)"
  if ! LIBGUESTFS_BACKEND=direct libguestfs-test-tool; then
    echo "ERROR: libguestfs-test-tool failed. Fix the host libguestfs-tools installation before using Qlean image extraction." >&2
    exit 1
  fi
}

need_root
ensure_bridge_conf
ensure_bridge_helper_caps
ensure_qlean_network
maybe_install_guestfs_tools_ubuntu
verify_guestfs_runtime

echo "DONE"
