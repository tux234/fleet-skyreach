#!/usr/bin/bash
# enroll-tpm-key.sh
# Non-interactive TPM2 enrollment for mounted LUKS2 volumes.
# Intended to be run by Fleet as root on Linux hosts.

set -euo pipefail

# ---- Tunables (env) ---------------------------------------------------------
PCRS="${PCRS:-7}"                                         # Common: 7; optionally "7,11" etc.
MODE="${MODE:-apply}"                                     # "apply" or "dry-run" (default apply for Fleet)
MIN_SYSTEMD_CRYPTENROLL="${MIN_SYSTEMD_CRYPTENROLL:-245}" # require reasonable systemd
LOG_PREFIX="${LOG_PREFIX:-[tpm2-enroll]}"

# ---- Helpers ----------------------------------------------------------------
log() { echo "${LOG_PREFIX} $*"; }
warn() { echo "${LOG_PREFIX} WARN: $*" >&2; }
err() { echo "${LOG_PREFIX} ERROR: $*" >&2; }

need_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Missing required binary: $1"
    exit 1
  }
}

systemd_cryptenroll_version_ok() {
  local v raw
  raw="$(systemd-cryptenroll --version 2>/dev/null | head -n1 || true)"
  v="$(printf '%s\n' "$raw" | awk '{print $2}' | sed 's/[^0-9].*$//')"
  [[ -n "${v:-}" ]] || return 1
  [ "$v" -ge "$MIN_SYSTEMD_CRYPTENROLL" ]
}

resolve_chain() {
  local dev="$1"
  dev="$(readlink -f "$dev")" || true
  [[ -b "$dev" ]] || {
    warn "Not a block device: $dev"
    return 1
  }

  local crypt_kname
  # First check if this device itself is crypt
  if [[ "$(lsblk -no TYPE "$dev")" == "crypt" ]]; then
    crypt_kname="$(lsblk -no NAME "$dev")"
  else
    # Look for crypt device in the dependency chain (handles LVM-over-LUKS)
    crypt_kname="$(lsblk -srno NAME,TYPE "$dev" | awk '$2=="crypt"{print $1; exit}')"
    if [[ -z "$crypt_kname" ]]; then
      # Fallback: look for crypt children (original behavior)
      crypt_kname="$(lsblk -rno NAME,TYPE "$dev" | awk '$2=="crypt"{print $1; exit}')"
    fi
  fi
  
  if [[ -z "$crypt_kname" ]]; then
    return 1
  fi
  
  CRYPT_DEV="/dev/mapper/${crypt_kname}"
  # Handle dm_crypt-* naming - ensure /dev/mapper/ prefix
  [[ -b "$CRYPT_DEV" ]] || CRYPT_DEV="/dev/${crypt_kname}"

  # Get the underlying physical device for the crypt device
  # Use lsblk -s to trace dependencies and find the actual partition/disk
  local pk
  pk="$(lsblk -srno NAME,TYPE "$CRYPT_DEV" | awk '$2=="part"||$2=="disk"{print $1; exit}')"
  [[ -n "$pk" ]] || return 1
  PHYS_DEV="/dev/${pk}"
  return 0
}

is_luks2() {
  cryptsetup isLuks "$PHYS_DEV" &&
    cryptsetup luksDump "$PHYS_DEV" | grep -qE '^Version:\s*2$'
}

has_tpm2_token() {
  systemd-cryptenroll --dump "$PHYS_DEV" 2>/dev/null | awk '
    /^Token:[[:space:]]+[0-9]+$/ {in_tok=1}
    in_tok && /Type:[[:space:]]*systemd-tpm2/ {print "yes"; exit}
    /^$/ {in_tok=0}
  ' | grep -q '^yes$'
}

enroll_tpm2() {
  local dev="$1"
  if [[ "$MODE" == "dry-run" ]]; then
    log "DRY-RUN: systemd-cryptenroll --tpm2 --tpm2-pcrs=${PCRS} --device=${dev}"
    return 0
  fi
  export SYSTEMD_ASK_PASSWORD=0
  systemd-cryptenroll --tpm2 --tpm2-pcrs="${PCRS}" --device="${dev}"
}

# ---- Pre-flight --------------------------------------------------------------
need_bin lsblk
need_bin findmnt
need_bin cryptsetup
need_bin systemd-cryptenroll

if [[ ! -e /dev/tpmrm0 && ! -e /dev/tpm0 ]]; then
  err "No TPM device found (/dev/tpmrm0 or /dev/tpm0). On VMs, enable a vTPM."
  exit 1
fi

if ! systemd_cryptenroll_version_ok; then
  warn "systemd-cryptenroll is older than ${MIN_SYSTEMD_CRYPTENROLL}; behavior may vary. Continuing."
fi

log "Mode=${MODE} PCRS=${PCRS}"

# ---- Target discovery --------------------------------------------------------
mapfile -t TARGETS < <(
  lsblk -rpo NAME,TYPE,MOUNTPOINT | awk '
    $2!="loop" && length($3)>0 {print $1}
  ' | sort -u
)

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  log "No mounted block-backed filesystems found."
  exit 0
fi

CHANGED=0
for dev in "${TARGETS[@]}"; do
  if ! resolve_chain "$dev"; then
    continue
  fi

  if ! is_luks2; then
    warn "Skipping (not LUKS2): PHYS=${PHYS_DEV} (from ${dev})"
    continue
  fi

  if has_tpm2_token; then
    log "Already has TPM2 token: PHYS=${PHYS_DEV}"
    continue
  fi

  log "Enrolling TPM2: FS/LV=${dev} CRYPT=${CRYPT_DEV} PHYS=${PHYS_DEV}"
  if enroll_tpm2 "$PHYS_DEV"; then
    CHANGED=1
    systemd-cryptenroll --dump "$PHYS_DEV" || true

    # mark completion so the policy stops firing
    mkdir -p /var/lib/tpm-enroll
    echo "ok" >/var/lib/tpm-enroll/.root_enrolled
  else
    err "Enrollment failed for ${PHYS_DEV}"
  fi
done

if [[ $CHANGED -eq 0 ]]; then
  log "No changes (nothing eligible or already enrolled)."
fi
