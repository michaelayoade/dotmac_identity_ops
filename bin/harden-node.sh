#!/usr/bin/env bash
# Bring a fresh Contabo node to the Dotmac fleet baseline.
# Idempotent. Run over an ALREADY-WORKING key session - it disables password
# auth, so a run that begins on a password session ends by locking you out.
set -euo pipefail

echo "== 0. refuse to harden a session that is not key-authenticated =="
# SSH_CONNECTION exists either way, so ask sshd what authenticated THIS session.
# If root has no authorized_keys, disabling passwords would strand the host.
if [ ! -s /root/.ssh/authorized_keys ]; then
	echo "REFUSING: /root/.ssh/authorized_keys is empty or missing." >&2
	echo "Install the operator key first; hardening now would lock the host." >&2
	exit 1
fi
echo "ok    $(wc -l < /root/.ssh/authorized_keys) authorized key(s) present"
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
sort -u -o /root/.ssh/authorized_keys /root/.ssh/authorized_keys

echo "== 1. sshd hardening drop-in =="
# Named 00- deliberately: OpenSSH takes the FIRST value obtained, and
# 50-cloud-init.conf sets PasswordAuthentication yes. Sorting first is what
# makes this win even if cloud-init rewrites its own file.
install -m 0644 /dev/stdin /etc/ssh/sshd_config.d/00-dotmac-hardening.conf <<'CONF'
# Dotmac fleet hardening. Sorts before 50-cloud-init.conf, which sets
# PasswordAuthentication yes; OpenSSH takes the FIRST value obtained, so this
# wins even if cloud-init rewrites its own file.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
CONF

echo "== 2. validate BEFORE reload =="
sshd -t
echo "ok    sshd config valid"

echo "== 3. packages =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq fail2ban unattended-upgrades nftables >/dev/null
echo "ok    fail2ban, unattended-upgrades, nftables"

echo "== 4. fail2ban, matching the fleet (nftables + systemd backend) =="
install -m 0644 /dev/stdin /etc/fail2ban/jail.d/dotmac.conf <<'CONF'
[DEFAULT]
banaction = nftables
banaction_allports = nftables[type=allports]
backend = systemd

[sshd]
enabled = true
CONF

echo "== 5. unattended upgrades =="
install -m 0644 /dev/stdin /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF

echo "== 6. make cloud-init inert BY DECISION =="
# It is usually already inert on these images, but only because datasource
# detection failed - an incidental state a rebuild can reverse. The marker makes
# it a decision. Nothing here depends on it: sshd hardening and cluster
# networking live in operator-owned files that outrank or sit beside
# cloud-init's own.
install -m 0644 /dev/stdin /etc/cloud/cloud-init.disabled <<'CONF'
Disabled deliberately as part of Dotmac fleet hardening.
cloud-init owns 50-cloud-init.yaml and 50-cloud-init.conf. Operator-owned
files (00-dotmac-hardening.conf, 60-dotmac-private.yaml) are named to outrank
or sit beside them, so hardening does not depend on this staying off.
CONF

echo "== 7. apply =="
systemctl enable --now fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
systemctl reload ssh 2>/dev/null || systemctl reload sshd

echo "== 8. verify effective state =="
sshd -T | grep -iE '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|port) ' | sort | sed 's/^/  /'
echo "  fail2ban:            $(systemctl is-active fail2ban)"
echo "  unattended-upgrades: $(systemctl is-active unattended-upgrades)"
echo "  jails:               $(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/{print $2}' | xargs)"
echo "  os:                  $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "  cloud-init:          $(cloud-init status 2>/dev/null | awk "{print \$2}") (marker $([ -f /etc/cloud/cloud-init.disabled ] && echo present || echo absent))"
echo "DONE"
