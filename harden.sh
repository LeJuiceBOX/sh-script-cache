#!/usr/bin/env bash
# Terraria game server hardening script
# Run with: sudo bash /home/huntii/harden.sh

set -euo pipefail

RED='\033[0;31m'; YLW='\033[0;33m'; GRN='\033[0;32m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

echo "=========================================="
echo "  Terraria Server Security Hardening"
echo "=========================================="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    error "Must run as root: sudo bash $0"
    exit 1
fi

# ─── PREREQUISITE: Tailscale must be authenticated ───────────────────────────
echo "Checking Tailscale status..."
TS_IP=$(tailscale ip 2>/dev/null | head -1 || true)
if [[ -z "$TS_IP" ]]; then
    error "Tailscale is not authenticated."
    echo ""
    echo "  Run this first, then re-run the script:"
    echo "    sudo tailscale up"
    echo ""
    echo "  If you enable the firewall without Tailscale working you will lock"
    echo "  yourself out of SSH. Use the Proxmox console as a fallback."
    exit 1
fi
info "Tailscale authenticated — IP: $TS_IP"

# ─── 1. UFW FIREWALL ─────────────────────────────────────────────────────────
echo ""
echo "[1/10] Configuring UFW firewall..."

ufw --force reset

ufw default deny incoming
ufw default allow outgoing
# Do NOT change FORWARD default — Docker manages iptables FORWARD rules itself

# Tailscale WireGuard must reach the internet for peer connections
ufw allow in 41641/udp comment 'Tailscale WireGuard'

# Terraria: TCP for game traffic, UDP for some server features
ufw allow in on tailscale0 to any port 7777 proto tcp comment 'Terraria TCP'
ufw allow in on tailscale0 to any port 7777 proto udp comment 'Terraria UDP'

# SSH from local LAN
ufw allow in from 192.168.1.0/24 to any port 22 proto tcp comment 'SSH from LAN'

# Loopback always allowed
ufw allow in on lo comment 'Loopback'

ufw --force enable
info "UFW enabled — SSH and Terraria locked to tailscale0 interface only"
ufw status numbered

# ─── 2. SSH ───────────────────────────────────────────────────────────────────
echo ""
echo "[2/10] Hardening SSH..."

# Fix the main sshd_config (drop-in overrides but remove the ambiguity)
sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config

# Comprehensive hardened drop-in — overwrites the partial one
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'SSHEOF'
# Managed by harden.sh — do not edit by hand
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers huntii
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
Compression no
TCPKeepAlive no
MaxAuthTries 3
MaxStartups 3:50:10
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
SSHEOF

# Validate config before reloading
sshd -t
systemctl reload ssh
info "SSH hardened (root login disabled, password auth off, AllowUsers=huntii)"

# ─── 3. KERNEL PARAMETERS ─────────────────────────────────────────────────────
echo ""
echo "[3/10] Applying kernel hardening..."

cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTLEOF'
# Network — disable attack vectors
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log suspicious/forged packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Ignore broadcast pings (smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Strict reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Kernel information leaks
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# ASLR — full randomisation
kernel.randomize_va_space = 2

# Disable core dumps from SUID programs
fs.suid_dumpable = 0

# Unprivileged BPF — attackers use this for privilege escalation
kernel.unprivileged_bpf_disabled = 1

# Block kexec (prevents loading a new kernel without physical access)
kernel.kexec_load_disabled = 1

# Filesystem hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
SYSCTLEOF

sysctl -p /etc/sysctl.d/99-hardening.conf
info "Kernel parameters applied"

# ─── 4. DISABLE UNNECESSARY SERVICES ─────────────────────────────────────────
echo ""
echo "[4/10] Disabling unnecessary services..."

for svc in ModemManager multipathd; do
    if systemctl list-unit-files | grep -q "^${svc}.service"; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc"
        info "Masked: $svc"
    fi
done

# ─── 5. FAIL2BAN ──────────────────────────────────────────────────────────────
echo ""
echo "[5/10] Hardening Fail2ban..."

cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24
bantime  = 24h
findtime = 10m
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
bantime  = 48h
maxretry = 3
F2BEOF

systemctl restart fail2ban
info "Fail2ban: 48h SSH ban, LAN whitelisted (192.168.1.0/24), maxretry=3"

# ─── 6. SUID CLEANUP ──────────────────────────────────────────────────────────
echo ""
echo "[6/10] Removing unnecessary SUID bits..."

# ntfs-3g: only needed to mount NTFS drives (not relevant on this server)
# chsh / chfn: user shell/finger info changers, not needed on a single-user server
for bin in /usr/bin/ntfs-3g /usr/bin/chsh /usr/bin/chfn; do
    if [ -f "$bin" ] && [ -u "$bin" ]; then
        chmod -s "$bin"
        info "Removed SUID: $bin"
    fi
done

# ─── 7. PASSWORD POLICY ───────────────────────────────────────────────────────
echo ""
echo "[7/10] Applying password policy..."

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/'    /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/'       /etc/login.defs
sed -i 's/^LOG_OK_LOGINS.*/LOG_OK_LOGINS\tyes/'     /etc/login.defs
sed -i 's/^LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB\tyes/' /etc/login.defs

info "Password max age: never expires, login events: logged"

# ─── 8. PAM — REMOVE NULLOK ──────────────────────────────────────────────────
echo ""
echo "[8/10] Removing nullok from PAM..."
# nullok allows empty passwords — remove it
sed -i 's/\bnullok\b//g' /etc/pam.d/common-auth
info "nullok removed from PAM (empty passwords disallowed)"

# ─── 9. DOCKER HARDENING ──────────────────────────────────────────────────────
echo ""
echo "[9/10] Hardening Docker daemon..."

if systemctl is-active --quiet docker 2>/dev/null; then
    if [ ! -f /etc/docker/daemon.json ]; then
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json << 'DOCKEREOF'
{
  "icc": false,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false
}
DOCKEREOF
        systemctl restart docker
        info "Docker daemon hardened"
    else
        warn "/etc/docker/daemon.json already exists — skipped (review manually)"
    fi
else
    warn "Docker not running — skipped"
fi

# ─── 10. UNATTENDED UPGRADES ──────────────────────────────────────────────────
echo ""
echo "[10/10] Configuring unattended-upgrades..."

cat > /etc/apt/apt.conf.d/99-hardening-upgrades << 'UAEOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::SyslogEnable "true";
UAEOF

info "Auto-reboot for kernel updates at 04:00"

# ─── SUMMARY ──────────────────────────────────────────────────────────────────
echo ""
echo "=========================================="
echo "  HARDENING COMPLETE"
echo "=========================================="
echo ""
echo "Active firewall rules:"
ufw status numbered
echo ""
warn "NEXT STEPS:"
echo "  1. Open a NEW SSH session via Tailscale to confirm access before closing this one"
echo "  2. Reboot to fully apply kernel parameter changes: sudo reboot"
echo "  3. After reboot, run: sudo ufw status && sudo fail2ban-client status"
echo "  4. If you use Docker for Terraria: remove 'huntii' from docker group or"
echo "     run the container as a non-root user with --user flag"
echo "  5. Set up Terraria server — port 7777 is already open on tailscale0"
echo ""
warn "Do NOT close this session until you verify SSH works in a new window!"

