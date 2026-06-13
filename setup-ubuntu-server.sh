#!/usr/bin/env bash
#
# Ubuntu Server Hardening & Setup Script
# ---------------------------------------
# Performs initial system hardening, user account creation, firewall +
# fail2ban configuration, Docker installation, and (optionally) Tailscale.
#
# Review the CONFIGURATION block below and fill in the required values
# BEFORE running. Run as root (sudo). For the most reliable lockout
# guardrail, run with:  sudo -E ./harden.sh
#-----------------------------------------
# Installation
# 1. Download
#curl -fsSL https://raw.githubusercontent.com/LeJuiceBOX/sh-script-cache/refs/heads/main/setup-ubuntu-server.sh -o setup.sh

# 2. Edit the config block (SSH_PUBLIC_KEY is required)
#nano setup.sh
#-----------------------------------------

#set -euo pipefail

# ======================================================================
# Configuration  --  EDIT THESE BEFORE RUNNING
# ======================================================================
LOG_FILE="/var/log/hardening.log"

# --- User account ---
NEW_USER="admin"

# Paste the PUBLIC key (contents of your *.pub file). REQUIRED.
# If empty, the script aborts before it can lock you out.
SSH_PUBLIC_KEY=""

# Prompt to set a login password for the new user so they can use sudo.
# "true"  = the script pauses and asks you to type a password (recommended).
# "false" = no password set; sudo won't work until you set one manually or
#           add a NOPASSWD rule. SSH stays key-only either way.
SET_SUDO_PASSWORD="true"

# --- Firewall ---
# Local network allowed to reach SSH, in CIDR form (e.g. 192.168.1.0/24).
# Leave empty to auto-detect the server's primary LAN subnet.
SSH_ALLOW_CIDR=""

# --- Docker (optional) ---
# Set to "true" to install Docker. The user is NOT added to the docker
# group, so Docker commands require sudo.
INSTALL_DOCKER="true"

# --- git (optional) ---
# Set to "true" to install git.
INSTALL_GIT="false"

# Optional GitHub SSH key for the new user (e.g. a deploy or read key)
# so they can clone/pull private repos via git@github.com.
# Paste the PRIVATE key contents (the whole file, including the
# BEGIN/END lines). Leave empty to skip. Requires INSTALL_GIT="true".
# NOTE: storing a private key in this file is sensitive — see the notes
# printed after the run. A read-only deploy key is the safest choice.
GITHUB_SSH_PRIVATE_KEY=""

# --- Tailscale (optional) ---
# Set to "true" to install Tailscale.
INSTALL_TAILSCALE="false"
# Optional pre-auth key for unattended bring-up. If empty, the script
# installs Tailscale and leaves it for you to run 'sudo tailscale up'.
TAILSCALE_AUTHKEY=""

# --- Cleanup ---
# Set to "true" to delete this script's log file after the run finishes.
# On-screen output is unaffected; only the persistent log is removed.
DELETE_LOGS_AFTER="true"

# ======================================================================
# Internal state  --  do not edit
# ======================================================================
WARNINGS=()
STEP_UPDATES_DONE=false
STEP_USER_DONE=false
STEP_PWD_DONE=false
STEP_SSH_DONE=false
STEP_UFW_DONE=false
STEP_F2B_DONE=false
STEP_DOCKER_DONE=false
STEP_GIT_DONE=false
STEP_GITHUB_KEY_DONE=false
STEP_TAILSCALE_DONE=false

# ======================================================================
# Helper functions
# ======================================================================
if [[ -t 1 ]]; then
    C_RESET="\033[0m"
    C_INFO="\033[0;34m"    # blue
    C_OK="\033[0;32m"      # green
    C_WARN="\033[0;33m"    # yellow
    C_ERR="\033[0;31m"     # red
else
    C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""
fi

log()     { echo -e "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG_FILE"; }
info()    { log "${C_INFO}[INFO]${C_RESET} $*"; }
success() { log "${C_OK}[ OK ]${C_RESET} $*"; }
warn()    { log "${C_WARN}[WARN]${C_RESET} $*"; WARNINGS+=("$*"); }
error()   { log "${C_ERR}[FAIL]${C_RESET} $*"; WARNINGS+=("$*"); }

die() {
    error "$*"
    exit 1
}

# ======================================================================
# Final summary  --  registered as an EXIT trap so it ALWAYS runs and
# lists every warning/error recorded, even on an aborted run.
# ======================================================================
print_summary() {
    local rc=$?
    echo ""
    log "======================================================================"
    log "                          RUN SUMMARY"
    log "======================================================================"

    if [[ "${rc}" -eq 0 ]]; then
        success "Script finished with exit code 0."
    else
        error "Script aborted with exit code ${rc}."
    fi

    log ""
    log "Completed steps:"
    log "  [$([[ ${STEP_UPDATES_DONE}   == true ]] && echo x || echo ' ')] System updates & essential packages"
    log "  [$([[ ${STEP_USER_DONE}      == true ]] && echo x || echo ' ')] User account: ${NEW_USER}"
    log "  [$([[ ${STEP_PWD_DONE}       == true ]] && echo x || echo ' ')] Sudo password set for ${NEW_USER}"
    log "  [$([[ ${STEP_SSH_DONE}       == true ]] && echo x || echo ' ')] SSH hardening"
    log "  [$([[ ${STEP_UFW_DONE}       == true ]] && echo x || echo ' ')] Firewall (UFW), SSH from: ${SSH_ALLOW_CIDR:-unset}"
    log "  [$([[ ${STEP_F2B_DONE}       == true ]] && echo x || echo ' ')] fail2ban"
    log "  [$([[ ${STEP_DOCKER_DONE}    == true ]] && echo x || echo ' ')] Docker (sudo-gated, user NOT in docker group)"
    log "  [$([[ ${STEP_GIT_DONE}       == true ]] && echo x || echo ' ')] git (optional)"
    log "  [$([[ ${STEP_GITHUB_KEY_DONE} == true ]] && echo x || echo ' ')] GitHub SSH key for ${NEW_USER} (optional)"
    log "  [$([[ ${STEP_TAILSCALE_DONE} == true ]] && echo x || echo ' ')] Tailscale (optional)"

    log ""
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        log "${C_WARN}Errors / warnings recorded during this run (${#WARNINGS[@]}):${C_RESET}"
        local i=1
        for w in "${WARNINGS[@]}"; do
            log "  ${i}. ${w}"
            i=$((i + 1))
        done
    else
        success "No errors or warnings were recorded."
    fi

    log ""
    if [[ -f /var/run/reboot-required ]]; then
        warn "A reboot is required (likely a kernel/library upgrade)."
        log "  Run: sudo reboot"
    fi

    log ""
    log "${C_WARN}IMPORTANT:${C_RESET} Keep your CURRENT SSH session open."
    log "Open a NEW terminal and verify you can log in as '${NEW_USER}' via key"
    log "BEFORE you disconnect — password login and root login are now disabled."
    if [[ "${DELETE_LOGS_AFTER}" == "true" ]]; then
        log "Setup log will be deleted now (DELETE_LOGS_AFTER=true)."
    else
        log "Full log: ${LOG_FILE}"
    fi
    log "======================================================================"

    # Must be the very last action: remove the persistent log file.
    # On-screen output above is unaffected.
    if [[ "${DELETE_LOGS_AFTER}" == "true" ]]; then
        rm -f "${LOG_FILE}" 2>/dev/null || true
    fi
}

# ======================================================================
# Pre-flight checks
# ======================================================================
preflight_checks() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This script must be run as root (use sudo)."
    fi

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ "${ID:-}" != "ubuntu" ]]; then
            die "This script targets Ubuntu Server. Detected: ${ID:-unknown}."
        fi
        info "Detected Ubuntu ${VERSION_ID:-unknown} (${VERSION_CODENAME:-?})."
    else
        die "/etc/os-release not found; cannot verify OS."
    fi

    touch "$LOG_FILE" 2>/dev/null || die "Cannot write to log file: $LOG_FILE"
    success "Pre-flight checks passed."
}

# ======================================================================
# Step 2: System updates & essential packages
# ======================================================================
ESSENTIAL_PACKAGES=(
    curl
    ca-certificates
    gnupg
    lsb-release
    ufw
    fail2ban
    unattended-upgrades
    apt-listchanges
)

system_update() {
    info "Updating package lists..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >>"$LOG_FILE" 2>&1 || die "apt-get update failed."

    info "Upgrading installed packages (this may take a while)..."
    apt-get upgrade -y >>"$LOG_FILE" 2>&1 || die "apt-get upgrade failed."
    success "System packages upgraded."
}

install_essentials() {
    info "Installing essential packages: ${ESSENTIAL_PACKAGES[*]}"
    apt-get install -y "${ESSENTIAL_PACKAGES[@]}" >>"$LOG_FILE" 2>&1 \
        || die "Failed to install essential packages."
    success "Essential packages installed."
}

enable_auto_updates() {
    info "Enabling unattended security upgrades..."
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    systemctl enable --now unattended-upgrades >>"$LOG_FILE" 2>&1 \
        || warn "Could not enable unattended-upgrades service."
    success "Automatic security updates enabled."
}

cleanup_packages() {
    info "Removing orphaned packages..."
    apt-get autoremove -y >>"$LOG_FILE" 2>&1 || warn "autoremove reported an issue."
    apt-get autoclean -y >>"$LOG_FILE" 2>&1 || true
    success "Cleanup complete."
}

# ======================================================================
# Step 3: User account creation
# ======================================================================

# Interactively set a login password for NEW_USER so they can use sudo.
# Reads from /dev/tty (works even when stdin is a pipe). Non-fatal: if no
# terminal is available, it warns and leaves the account password-disabled.
# The password is never echoed or written to the log.
set_user_password() {
    info "Setting a login password for '${NEW_USER}' (required for sudo)..."

    if [[ ! -e /dev/tty ]]; then
        warn "No terminal available to prompt for a password. '${NEW_USER}' \
cannot use sudo until you run: passwd ${NEW_USER}"
        return 1
    fi

    local attempts=0
    while (( attempts < 3 )); do
        if passwd "${NEW_USER}" < /dev/tty; then
            success "Password set for '${NEW_USER}'."
            return 0
        fi
        attempts=$(( attempts + 1 ))
        warn "Password not set (attempt ${attempts}/3)."
    done

    warn "Could not set a password after 3 attempts; run 'passwd ${NEW_USER}' \
manually before using sudo."
    return 1
}

create_user() {
    if [[ -z "${NEW_USER}" ]]; then
        die "NEW_USER is not set in the configuration block."
    fi

    if [[ -z "${SSH_PUBLIC_KEY}" ]]; then
        die "SSH_PUBLIC_KEY is empty. Set it before running, or you risk \
being locked out when password authentication is disabled later."
    fi

    if id "${NEW_USER}" &>/dev/null; then
        warn "User '${NEW_USER}' already exists; skipping creation."
    else
        info "Creating user '${NEW_USER}'..."
        adduser --disabled-password --gecos "" "${NEW_USER}" >>"$LOG_FILE" 2>&1 \
            || die "Failed to create user '${NEW_USER}'."
        success "User '${NEW_USER}' created."
    fi

    info "Adding '${NEW_USER}' to the sudo group..."
    usermod -aG sudo "${NEW_USER}" || die "Failed to add user to sudo group."
    success "'${NEW_USER}' now has sudo privileges."

    # Set a sudo password if requested (key-only SSH is unaffected).
    if [[ "${SET_SUDO_PASSWORD}" == "true" ]]; then
        if set_user_password; then
            STEP_PWD_DONE=true
        fi
    else
        warn "SET_SUDO_PASSWORD is not 'true'; no password set. '${NEW_USER}' \
cannot use sudo until you set one (passwd ${NEW_USER}) or add a NOPASSWD rule."
    fi

    local ssh_dir="/home/${NEW_USER}/.ssh"
    local auth_keys="${ssh_dir}/authorized_keys"

    info "Installing SSH public key for '${NEW_USER}'..."
    mkdir -p "${ssh_dir}"

    if [[ -f "${auth_keys}" ]] && grep -qF "${SSH_PUBLIC_KEY}" "${auth_keys}"; then
        warn "Public key already present; not adding a duplicate."
    else
        echo "${SSH_PUBLIC_KEY}" >> "${auth_keys}"
    fi

    chmod 700 "${ssh_dir}"
    chmod 600 "${auth_keys}"
    chown -R "${NEW_USER}:${NEW_USER}" "${ssh_dir}"
    success "SSH key installed for '${NEW_USER}'."

    if [[ ! -s "${auth_keys}" ]]; then
        die "authorized_keys is empty after install; aborting to prevent lockout."
    fi
}

# ======================================================================
# Step 4: SSH hardening
# ======================================================================
harden_ssh() {
    local dropin="/etc/ssh/sshd_config.d/99-hardening.conf"
    local auth_keys="/home/${NEW_USER}/.ssh/authorized_keys"

    if [[ ! -s "${auth_keys}" ]]; then
        die "No authorized_keys for '${NEW_USER}'; refusing to harden SSH \
(would cause lockout). Run create_user first."
    fi

    info "Writing SSH hardening drop-in to ${dropin}..."
    cat > "${dropin}" <<EOF
# Managed by hardening script — do not edit by hand.
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PubkeyAuthentication yes
AllowUsers ${NEW_USER}
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    chmod 644 "${dropin}"

    info "Validating sshd configuration..."
    if ! sshd -t >>"$LOG_FILE" 2>&1; then
        rm -f "${dropin}"
        die "sshd config validation failed; reverted drop-in. SSH left untouched."
    fi

    info "Reloading SSH service..."
    systemctl reload ssh >>"$LOG_FILE" 2>&1 \
        || systemctl reload sshd >>"$LOG_FILE" 2>&1 \
        || die "Failed to reload SSH service."

    success "SSH hardened: root login and password auth disabled."
    warn "Keep your current session OPEN. Test a new SSH login as \
'${NEW_USER}' before disconnecting."
}

# ======================================================================
# Step 5: Firewall (UFW)
# ======================================================================
_ip_to_int() {
    local IFS=. a b c d
    read -r a b c d <<< "$1"
    echo "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
}

ip_in_cidr() {
    local ip="$1" cidr="$2"
    local network="${cidr%/*}" prefix="${cidr#*/}"
    local ip_int net_int mask
    ip_int="$(_ip_to_int "$ip")"
    net_int="$(_ip_to_int "$network")"
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    [[ $(( ip_int & mask )) -eq $(( net_int & mask )) ]]
}

detect_ssh_client_ip() {
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        echo "${SSH_CONNECTION%% *}"
        return 0
    fi
    who am i 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

detect_lan_cidr() {
    local cidr
    cidr="$(ip -o -f inet addr show scope global | awk '{print $4}' | head -n1)" || return 1
    [[ -n "$cidr" ]] || return 1
    local ip="${cidr%/*}"
    echo "${ip%.*}.0/24"
}

configure_firewall() {
    if [[ -z "${SSH_ALLOW_CIDR}" ]]; then
        SSH_ALLOW_CIDR="$(detect_lan_cidr)" \
            || die "Could not auto-detect LAN subnet; set SSH_ALLOW_CIDR manually."
        warn "SSH_ALLOW_CIDR not set; auto-detected ${SSH_ALLOW_CIDR}."
    fi
    info "Restricting SSH to ${SSH_ALLOW_CIDR}."

    local client_ip
    client_ip="$(detect_ssh_client_ip || true)"
    if [[ -n "${client_ip}" ]]; then
        if ip_in_cidr "${client_ip}" "${SSH_ALLOW_CIDR}"; then
            info "Current SSH client ${client_ip} is within the allowed range."
        else
            die "Current SSH client ${client_ip} is OUTSIDE ${SSH_ALLOW_CIDR}. \
Enabling this rule would lock you out. Fix SSH_ALLOW_CIDR and re-run."
        fi
    else
        warn "Could not determine the current client IP (console session?). \
Proceeding — double-check ${SSH_ALLOW_CIDR} is correct."
    fi

    info "Setting UFW defaults: deny incoming, allow outgoing..."
    ufw default deny incoming  >>"$LOG_FILE" 2>&1 || die "Failed to set default deny incoming."
    ufw default allow outgoing >>"$LOG_FILE" 2>&1 || die "Failed to set default allow outgoing."

    info "Allowing (rate-limited) SSH from ${SSH_ALLOW_CIDR}..."
    ufw limit from "${SSH_ALLOW_CIDR}" to any port 22 proto tcp >>"$LOG_FILE" 2>&1 \
        || die "Failed to add SSH firewall rule."

    info "Enabling UFW..."
    ufw --force enable >>"$LOG_FILE" 2>&1 || die "Failed to enable UFW."

    success "Firewall active: all incoming denied except SSH from ${SSH_ALLOW_CIDR}."
    ufw status verbose | tee -a "$LOG_FILE"
}

# ======================================================================
# Step 6: fail2ban
# ======================================================================
configure_fail2ban() {
    local jail="/etc/fail2ban/jail.local"

    local ignore="127.0.0.1/8 ::1"
    if [[ -n "${SSH_ALLOW_CIDR:-}" ]]; then
        ignore="${ignore} ${SSH_ALLOW_CIDR}"
    fi

    info "Writing fail2ban configuration to ${jail}..."
    cat > "${jail}" <<EOF
# Managed by hardening script — do not edit by hand.
[DEFAULT]
ignoreip = ${ignore}
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
port    = ssh
EOF
    chmod 644 "${jail}"

    info "Enabling and starting fail2ban..."
    systemctl enable --now fail2ban >>"$LOG_FILE" 2>&1 \
        || die "Failed to enable/start fail2ban."

    sleep 2
    if fail2ban-client status sshd >>"$LOG_FILE" 2>&1; then
        success "fail2ban active; sshd jail is running."
    else
        warn "fail2ban started but the sshd jail did not report status; \
check 'fail2ban-client status sshd'."
    fi
}

# ======================================================================
# Step 7: Docker installation (sudo-gated; user NOT added to docker group)
# ======================================================================
install_docker() {
    local keyring="/etc/apt/keyrings/docker.asc"
    local repo_list="/etc/apt/sources.list.d/docker.list"

    info "Removing conflicting legacy Docker packages (if any)..."
    apt-get remove -y docker docker-engine docker.io containerd runc \
        >>"$LOG_FILE" 2>&1 || true

    info "Adding Docker's official GPG key..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "${keyring}" \
        || { warn "Failed to download Docker GPG key."; return 1; }
    chmod a+r "${keyring}"

    info "Adding Docker apt repository..."
    local arch codename
    arch="$(dpkg --print-architecture)"
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
    echo "deb [arch=${arch} signed-by=${keyring}] \
https://download.docker.com/linux/ubuntu ${codename} stable" > "${repo_list}"

    info "Updating package lists with Docker repo..."
    apt-get update -y >>"$LOG_FILE" 2>&1 \
        || { warn "apt-get update failed after adding Docker repo."; return 1; }

    info "Installing Docker Engine, CLI, containerd, and plugins..."
    apt-get install -y \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin \
        >>"$LOG_FILE" 2>&1 || { warn "Failed to install Docker packages."; return 1; }

    info "Enabling and starting Docker service..."
    systemctl enable --now docker >>"$LOG_FILE" 2>&1 \
        || { warn "Failed to enable/start Docker."; return 1; }

    # Deliberately NOT adding ${NEW_USER} to the 'docker' group.
    # Docker group membership is root-equivalent; requiring 'sudo docker'
    # keeps that privilege explicit.
    info "Leaving '${NEW_USER}' OUT of the docker group by design; \
Docker commands will require sudo."

    local docker_ver compose_ver
    docker_ver="$(docker --version 2>/dev/null || true)"
    compose_ver="$(docker compose version 2>/dev/null || true)"
    [[ -n "${docker_ver}" ]] || { warn "Docker install verification failed."; return 1; }
    success "Installed: ${docker_ver}"
    [[ -n "${compose_ver}" ]] && success "Compose plugin: ${compose_ver}"
}

# ======================================================================
# Optional: git installation
# ======================================================================
install_git() {
    info "Installing git (optional step)..."
    apt-get install -y git >>"$LOG_FILE" 2>&1 \
        || { warn "Failed to install git."; return 1; }
    success "git installed: $(git --version 2>/dev/null || echo 'version unknown')"
}

# ----------------------------------------------------------------------
# Optional: install a GitHub SSH key for NEW_USER (deploy/read key)
# so they can use git@github.com for private repos. The private key is
# written directly to the user's ~/.ssh with 600 perms and is never
# echoed to the log.
# ----------------------------------------------------------------------
configure_github_key() {
    if [[ -z "${GITHUB_SSH_PRIVATE_KEY}" ]]; then
        info "No GITHUB_SSH_PRIVATE_KEY provided; skipping GitHub key setup."
        return 0
    fi

    if ! command -v git &>/dev/null; then
        warn "GitHub key provided but git is not installed; skipping. \
Set INSTALL_GIT=\"true\"."
        return 1
    fi

    local ssh_dir="/home/${NEW_USER}/.ssh"
    local key_file="${ssh_dir}/github_id"
    local cfg_file="${ssh_dir}/config"
    local known="${ssh_dir}/known_hosts"

    info "Installing GitHub SSH key for '${NEW_USER}'..."
    mkdir -p "${ssh_dir}"

    # Write the private key WITHOUT routing through the log.
    printf '%s\n' "${GITHUB_SSH_PRIVATE_KEY}" > "${key_file}"
    chmod 600 "${key_file}"

    # Add an SSH config entry so git@github.com uses this key.
    if [[ ! -f "${cfg_file}" ]] || ! grep -q "Host github.com" "${cfg_file}"; then
        cat >> "${cfg_file}" <<EOF

Host github.com
    HostName github.com
    User git
    IdentityFile ${key_file}
    IdentitiesOnly yes
EOF
        chmod 600 "${cfg_file}"
    fi

    # Pin GitHub's host keys so the first clone doesn't prompt.
    info "Adding github.com to known_hosts..."
    if ssh-keyscan -t rsa,ecdsa,ed25519 github.com >> "${known}" 2>>"$LOG_FILE"; then
        # De-duplicate in case the script is re-run.
        sort -u "${known}" -o "${known}"
        chmod 644 "${known}"
    else
        warn "ssh-keyscan for github.com failed (no network?); \
the first clone may prompt to verify the host key."
    fi

    chown -R "${NEW_USER}:${NEW_USER}" "${ssh_dir}"
    success "GitHub SSH key configured for '${NEW_USER}'."
}

# ======================================================================
# Optional: Tailscale installation
# ======================================================================
install_tailscale() {
    info "Installing Tailscale (optional step)..."

    local codename keyring="/usr/share/keyrings/tailscale-archive-keyring.gpg"
    local repo_list="/etc/apt/sources.list.d/tailscale.list"
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"

    info "Adding Tailscale's package signing key and repository..."
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.noarmor.gpg" \
        -o "${keyring}" || { warn "Failed to fetch Tailscale GPG key."; return 1; }
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.tailscale-keyring.list" \
        -o "${repo_list}" || { warn "Failed to fetch Tailscale repo list."; return 1; }

    apt-get update -y >>"$LOG_FILE" 2>&1 \
        || { warn "apt-get update failed after adding Tailscale repo."; return 1; }
    apt-get install -y tailscale >>"$LOG_FILE" 2>&1 \
        || { warn "Failed to install the tailscale package."; return 1; }

    systemctl enable --now tailscaled >>"$LOG_FILE" 2>&1 \
        || { warn "Failed to enable/start tailscaled."; return 1; }

    # Allow SSH in over the Tailscale interface so you retain an admin path
    # even though UFW restricts normal SSH to the LAN subnet.
    if command -v ufw &>/dev/null; then
        info "Allowing SSH in over the tailscale0 interface..."
        ufw allow in on tailscale0 to any port 22 proto tcp \
            comment 'SSH over Tailscale' >>"$LOG_FILE" 2>&1 \
            || warn "Could not add the tailscale0 SSH firewall rule."
    fi

    if [[ -n "${TAILSCALE_AUTHKEY}" ]]; then
        info "Bringing Tailscale up with the provided auth key..."
        tailscale up --authkey "${TAILSCALE_AUTHKEY}" >>"$LOG_FILE" 2>&1 \
            || { warn "'tailscale up' failed; run 'sudo tailscale up' manually."; return 1; }
        success "Tailscale is up. Node IP: $(tailscale ip -4 2>/dev/null || echo 'unknown')"
    else
        success "Tailscale installed."
        warn "No auth key provided. Run 'sudo tailscale up' to connect this node."
    fi
}

# ======================================================================
# Main
# ======================================================================
main() {
    trap print_summary EXIT

    info "Starting Ubuntu Server hardening & setup..."
    preflight_checks

    # Step 2: Updates & essentials
    system_update
    install_essentials
    enable_auto_updates
    cleanup_packages
    STEP_UPDATES_DONE=true

    # Step 3: User account
    create_user
    STEP_USER_DONE=true

    # Step 4: SSH hardening
    harden_ssh
    STEP_SSH_DONE=true

    # Step 5: Firewall
    configure_firewall
    STEP_UFW_DONE=true

    # Step 6: fail2ban
    configure_fail2ban
    STEP_F2B_DONE=true

    # Step 7: Docker (optional, non-fatal — failure won't abort the run)
    if [[ "${INSTALL_DOCKER}" == "true" ]]; then
        if install_docker; then
            STEP_DOCKER_DONE=true
        else
            warn "Docker step did not complete successfully."
        fi
    else
        info "Skipping Docker (INSTALL_DOCKER != true)."
    fi

    # Optional: git
    if [[ "${INSTALL_GIT}" == "true" ]]; then
        if install_git; then
            STEP_GIT_DONE=true
        else
            warn "git step did not complete successfully."
        fi
    else
        info "Skipping git (INSTALL_GIT != true)."
    fi

    # Optional: GitHub SSH key (only meaningful once git is present)
    if [[ -n "${GITHUB_SSH_PRIVATE_KEY}" ]]; then
        if configure_github_key; then
            STEP_GITHUB_KEY_DONE=true
        else
            warn "GitHub key step did not complete successfully."
        fi
    fi

    # Optional: Tailscale (non-fatal — failure won't abort the run)
    if [[ "${INSTALL_TAILSCALE}" == "true" ]]; then
        if install_tailscale; then
            STEP_TAILSCALE_DONE=true
        else
            warn "Tailscale step did not complete successfully."
        fi
    else
        info "Skipping Tailscale (INSTALL_TAILSCALE != true)."
    fi

    success "All requested steps processed."
    # print_summary runs automatically via the EXIT trap.
}

main "$@"
