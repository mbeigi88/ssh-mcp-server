#!/usr/bin/env bash
# One-time setup of the REAL OpenSSH test server used by the integration tests (Debian/Ubuntu, needs sudo).
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
KEYS="$DIR/fixtures/keys"
if ! [ -x /usr/sbin/sshd ]; then
  sudo -n apt-get update -qq
  sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server openssh-client >/dev/null
fi
id sshtest >/dev/null 2>&1 || sudo -n useradd -m -s /bin/bash sshtest
echo 'sshtest:T3stPassw0rd!' | sudo -n chpasswd
sudo -n mkdir -p /home/sshtest/.ssh
cat "$KEYS"/id_ed25519.pub "$KEYS"/id_rsa.pub "$KEYS"/id_ed25519_enc.pub "$KEYS"/id_ecdsa.pub | sudo -n tee /home/sshtest/.ssh/authorized_keys >/dev/null
sudo -n chown -R sshtest:sshtest /home/sshtest/.ssh
sudo -n chmod 700 /home/sshtest/.ssh; sudo -n chmod 600 /home/sshtest/.ssh/authorized_keys
echo "test sshd prerequisites ready"
