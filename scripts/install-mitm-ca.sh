#!/usr/bin/env bash
# install-mitm-ca.sh — push mitmproxy's CA cert to the connected device
# as a SYSTEM trust anchor via a Magisk module.
#
# Why this exists: Android 7+ ignores user-installed CAs for app traffic.
# The mitmproxy cert MUST live in /system/etc/security/cacerts/. The
# canonical way to put it there on a rooted device is a Magisk module
# that bind-mounts a writable cacerts directory at boot. This script
# generates that module on the fly and installs it.
#
# Requirements (script aborts if any are missing):
#   - adb on PATH
#   - One device connected with USB debug authorised
#   - Device has Magisk installed (we check via `magisk -v`)
#   - mitmproxy has been run at least once (CA in ~/.mitmproxy/)
#
# Usage:
#   scripts/install-mitm-ca.sh                    # auto-detect device
#   scripts/install-mitm-ca.sh -s <serial>        # specific device
#   scripts/install-mitm-ca.sh --uninstall        # remove the module
#
set -euo pipefail

# ---------- arg parsing ----------
DEVICE_SERIAL=""
ACTION="install"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--serial) DEVICE_SERIAL="$2"; shift 2 ;;
        --uninstall) ACTION="uninstall"; shift ;;
        -h|--help)
            sed -n '2,/^set -euo pipefail$/p' "$0" | sed 's/^# //; s/^#//'
            exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

ADB_ARGS=()
if [[ -n "$DEVICE_SERIAL" ]]; then
    ADB_ARGS+=(-s "$DEVICE_SERIAL")
fi

# ---------- preflight ----------
command -v adb >/dev/null 2>&1 || {
    echo "FATAL: adb not in PATH. Install Android platform-tools." >&2
    exit 1
}

DEVICE_COUNT=$(adb devices | grep -c -E "^\S+\s+device$" || true)
if [[ "$DEVICE_COUNT" -eq 0 ]]; then
    echo "FATAL: no Android device connected (or USB debug not authorised)." >&2
    exit 1
fi
if [[ "$DEVICE_COUNT" -gt 1 && -z "$DEVICE_SERIAL" ]]; then
    echo "FATAL: multiple devices connected. Use -s <serial>." >&2
    adb devices
    exit 1
fi

# Verify Magisk is present. Two probes — `magisk -v` works on most builds;
# `which magisk` is a backup for stripped images.
if ! adb "${ADB_ARGS[@]}" shell 'su -c "magisk -v"' 2>/dev/null | grep -q "magisk"; then
    if ! adb "${ADB_ARGS[@]}" shell 'su -c "which magisk"' 2>/dev/null | grep -q "magisk"; then
        echo "FATAL: Magisk not detected on device." >&2
        echo "       This script needs Magisk to install a system CA module." >&2
        echo "       Install Magisk first, then re-run." >&2
        exit 1
    fi
fi

MODULE_ID="sentinel-mitm-ca"
MODULE_DIR="/data/adb/modules/${MODULE_ID}"

# ---------- uninstall path ----------
if [[ "$ACTION" == "uninstall" ]]; then
    echo "[*] Removing Magisk module ${MODULE_ID}..."
    adb "${ADB_ARGS[@]}" shell "su -c 'touch ${MODULE_DIR}/remove'"
    echo "[*] Module marked for removal. Reboot the device to finish:"
    echo "    adb ${ADB_ARGS[*]:+\"${ADB_ARGS[*]}\" }reboot"
    exit 0
fi

# ---------- locate mitmproxy CA ----------
MITM_DIR="${HOME}/.mitmproxy"
MITM_CER="${MITM_DIR}/mitmproxy-ca-cert.cer"
if [[ ! -f "$MITM_CER" ]]; then
    echo "FATAL: mitmproxy CA not found at ${MITM_CER}." >&2
    echo "       Run \`mitmdump\` once first to generate it." >&2
    exit 1
fi

# Compute the Android subject_hash_old that determines the filename.
# OpenSSL ≥1.1 supports -subject_hash_old; if unavailable, fall back.
if ! command -v openssl >/dev/null 2>&1; then
    echo "FATAL: openssl not in PATH. Required to compute the cert hash." >&2
    exit 1
fi

HASH=$(openssl x509 -in "$MITM_CER" -inform PEM -subject_hash_old | head -n1)
if [[ -z "$HASH" ]]; then
    echo "FATAL: could not compute subject_hash_old from mitmproxy cert." >&2
    exit 1
fi

CERT_FILENAME="${HASH}.0"
echo "[*] mitmproxy CA hash: ${HASH} → /system/etc/security/cacerts/${CERT_FILENAME}"

# ---------- build the module locally ----------
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

MODULE_STAGE="${STAGE}/${MODULE_ID}"
mkdir -p "${MODULE_STAGE}/system/etc/security/cacerts"
cp "$MITM_CER" "${MODULE_STAGE}/system/etc/security/cacerts/${CERT_FILENAME}"

cat > "${MODULE_STAGE}/module.prop" <<EOF
id=${MODULE_ID}
name=SENTINEL mitmproxy CA
version=1.0
versionCode=1
author=SENTINEL
description=Installs the mitmproxy CA as a system trust anchor for DAST.
EOF

# Permissions matter — cacerts files are owned 0:0, mode 0644.
chmod -R u=rw,go=r "${MODULE_STAGE}"
find "${MODULE_STAGE}" -type d -exec chmod u=rwx,go=rx {} +

# ---------- push & install ----------
echo "[*] Pushing module to /data/local/tmp/..."
adb "${ADB_ARGS[@]}" push "${MODULE_STAGE}" /data/local/tmp/ >/dev/null

echo "[*] Moving into ${MODULE_DIR} (requires su)..."
adb "${ADB_ARGS[@]}" shell "su -c '
  set -e
  rm -rf ${MODULE_DIR}
  mkdir -p ${MODULE_DIR}
  cp -a /data/local/tmp/${MODULE_ID}/. ${MODULE_DIR}/
  chown -R 0:0 ${MODULE_DIR}
  chmod -R 0755 ${MODULE_DIR}
  find ${MODULE_DIR}/system/etc/security/cacerts -type f -exec chmod 0644 {} \;
  rm -rf /data/local/tmp/${MODULE_ID}
'"

echo "[*] Module installed. Reboot the device to activate:"
echo "    adb ${ADB_ARGS[*]:+\"${ADB_ARGS[*]}\" }reboot"
echo
echo "After the reboot, verify with:"
echo "    adb ${ADB_ARGS[*]:+\"${ADB_ARGS[*]}\" }shell 'ls /system/etc/security/cacerts/' | grep ${CERT_FILENAME}"
