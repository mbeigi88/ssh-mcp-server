#!/usr/bin/env bash
# Starts a REAL OpenSSH server on 127.0.0.1:2222 for integration tests.
# Requires sudo (sshd privilege separation) and openssh-server installed.
set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)"
KEYS="$DIR/fixtures/keys"
RUN=/tmp/cf-ssh-mcp-sshd
sudo -n mkdir -p /run/sshd "$RUN"
sudo -n cp "$KEYS"/host_ed25519 "$KEYS"/host_rsa "$KEYS"/host_ecdsa "$RUN"/
sudo -n chown root:root "$RUN"/host_*; sudo -n chmod 600 "$RUN"/host_*
sudo -n tee "$RUN/sshd_config" >/dev/null <<CFG
Port 2222
ListenAddress 127.0.0.1
HostKey $RUN/host_ed25519
HostKey $RUN/host_rsa
HostKey $RUN/host_ecdsa
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM yes
Subsystem sftp internal-sftp -l INFO
PidFile $RUN/sshd.pid
LogLevel VERBOSE
MaxAuthTries 10
CFG
if [ -f "$RUN/sshd.pid" ] && sudo -n kill -0 "$(sudo -n cat $RUN/sshd.pid)" 2>/dev/null; then echo "sshd already running"; exit 0; fi
sudo -n /usr/sbin/sshd -f "$RUN/sshd_config" -E "$RUN/sshd.log"
sleep 0.5
echo "sshd started on 127.0.0.1:2222"
