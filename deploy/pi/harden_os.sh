#!/usr/bin/env bash
set -euo pipefail

# Secure OS baseline for a SentinelEdgeAI appliance (Raspberry Pi OS / Debian, Jetson Ubuntu).
#
#   sudo bash deploy/pi/harden_os.sh                     # dry run: shows what would change
#   sudo bash deploy/pi/harden_os.sh --apply             # make the changes
#   MGMT_NETS="192.168.1.0/24" sudo bash ... --apply     # who may reach SSH and the console
#
# 1. SSH: keys only, no root login - refused if no user has an authorized key yet
#    (so you cannot lock yourself out).
# 2. Management firewall: SSH (22), console (9000) and sensor link (9443) accept new
#    connections only from MGMT_NETS (default: this device's own subnets). Other
#    services on the device are left alone unless --strict is given.
# 3. Automatic security updates (unattended-upgrades).
# 4. journald capped at 200 MB so logs cannot fill the disk.
# 5. LUKS disk encryption and a read-only root filesystem are printed as guidance:
#    both need a reinstall or an initramfs change that a script should not do blindly.

APPLY=0; STRICT=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --strict) STRICT=1 ;;
    *) echo "usage: $0 [--apply] [--strict]"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 2; }

say()  { printf '  %s\n' "$*"; }
step() { printf '\n[%s] %s\n' "$([ "$APPLY" = 1 ] && echo apply || echo dry-run)" "$*"; }
run()  { if [ "$APPLY" = 1 ]; then "$@"; else say "would run: $*"; fi; }
write() {  # write <path> <content>
  if [ "$APPLY" = 1 ]; then printf '%s\n' "$2" > "$1"; say "wrote $1"; else say "would write $1:"; printf '%s\n' "$2" | sed 's/^/      /'; fi
}

# ---------- 1. SSH ----------
step "SSH: key-only authentication"
KEYS=0
# root login is disabled below, so only a regular user's key keeps you able to log in
while IFS=: read -r user _ uid _ _ home _; do
  if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] && [ -s "$home/.ssh/authorized_keys" ]; then
    say "found authorized keys for $user"
    KEYS=1
  fi
done < /etc/passwd
if [ "$KEYS" = 0 ]; then
  say "SKIPPED: no regular user has ~/.ssh/authorized_keys (root's key does not count: root login gets"
  say "         disabled). Add your key first (ssh-copy-id you@this-device), then re-run."
else
  write /etc/ssh/sshd_config.d/50-sentineledgeai.conf "# SentinelEdgeAI hardening
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no"
  run sshd -t
  run systemctl reload ssh
fi

# ---------- 2. management firewall ----------
step "Management firewall"
if [ -z "${MGMT_NETS:-}" ]; then
  MGMT_NETS="$(ip -o -4 addr show scope global | awk '{print $4}' | grep -v '^172\.1[7-9]\.\|^172\.2[0-9]\.\|^10\.0\.' \
    | python3 -c 'import ipaddress,sys; print(",".join(sorted({str(ipaddress.ip_interface(l.strip()).network) for l in sys.stdin if l.strip()})))')"
fi
[ -n "$MGMT_NETS" ] || { say "could not determine MGMT_NETS; set it explicitly"; exit 1; }
say "management networks: $MGMT_NETS"
NFT="table inet sentinel_mgmt {
  set mgmt4 { type ipv4_addr; flags interval; elements = { ${MGMT_NETS} } }
  chain input {
    type filter hook input priority -5; policy accept;
    ct state established,related accept
    iif lo accept
    tcp dport { 22, 9000, 9443 } ip saddr @mgmt4 accept
    tcp dport { 22, 9000, 9443 } ct state new drop$( if [ "$STRICT" = 1 ]; then printf '\n    meta l4proto { icmp, ipv6-icmp } accept\n    udp sport 67 udp dport 68 accept\n    ct state new drop'; fi )
  }
}"
write /etc/nftables.d/sentineledgeai-mgmt.nft "$NFT"
if [ "$APPLY" = 1 ]; then
  mkdir -p /etc/nftables.d
  nft list table inet sentinel_mgmt >/dev/null 2>&1 && nft delete table inet sentinel_mgmt
  nft -f /etc/nftables.d/sentineledgeai-mgmt.nft
  grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null \
    || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
  systemctl enable nftables >/dev/null 2>&1 || true
  say "rules loaded and persisted (nftables.service)"
fi

# ---------- 3. automatic security updates ----------
step "Automatic security updates"
if command -v apt-get >/dev/null; then
  run apt-get install -y unattended-upgrades
  write /etc/apt/apt.conf.d/20auto-upgrades 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";'
else
  say "not a Debian-based system; enable your distribution's automatic updates"
fi

# ---------- 4. journald ----------
step "Log size limit"
write /etc/systemd/journald.conf.d/50-sentineledgeai.conf "[Journal]
SystemMaxUse=200M
MaxRetentionSec=30day"
run systemctl restart systemd-journald

# ---------- 5. guidance ----------
step "Disk encryption and read-only root (manual)"
say "LUKS: encrypt the data partition at install time (Raspberry Pi: install to NVMe with a LUKS root via"
say "      cryptsetup + initramfs; Jetson: use the JetPack disk-encryption flow). Keep the key off the device"
say "      or use clevis+tang so the appliance unlocks only on its own network."
say "Read-only root: Raspberry Pi OS supports an overlay root (raspi-config nonint do_overlayfs 0)."
say "      SentinelEdgeAI keeps all state in /var/lib/sentinel and /var/log/sentinel - mount those"
say "      read-write and the rest of the system can be read-only."

if [ "$APPLY" = 0 ]; then
  printf '\nDry run only. Re-run with --apply to make these changes.\n'
fi
