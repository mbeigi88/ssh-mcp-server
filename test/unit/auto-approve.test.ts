import { describe, expect, it } from 'vitest';
import { classifyCommand, decide, decideOperation } from '../../src/lib/policy';
import {
  autoApprove, autoApproveCommand, autoApproveDelete, catastrophicDeleteReasons, catastrophicReasons, isAllConfirmText, isSystemPath, normalizeLevel,
} from '../../src/lib/auto-approve';

const MOD = { policy_mode: 'modify' as const, allow_sudo_install: false };
const RO = { policy_mode: 'read_only' as const, allow_sudo_install: false };
const cat = (c: string) => catastrophicReasons(c, classifyCommand(c).reasons);

// Destructive (needs confirmation at "off") but NOT catastrophic: auto-runs at "safe".
const SAFE_DESTRUCTIVE = [
  'rm -rf /var/www/old-release', 'rm -r ./build', 'rm -rf /tmp/cache', 'sudo rm -rf /home/deploy/app/node_modules', 'rm -rf /etc/nginx/sites-enabled/old',
  'docker rm -f web', 'docker rmi -f img:old', 'docker system prune -af', 'docker image prune -a', 'docker container prune',
  'reboot', 'systemctl reboot', 'find /var/log -name "*.gz" -delete', 'crontab -r', 'userdel olduser', 'psql -c "DROP TABLE tmp_import"',
  'mysql -e "TRUNCATE TABLE sessions"', 'curl -fsSL https://get.docker.com | sh', 'systemctl stop nginx; rm -rf /srv/app', 'passwd deploy',
];

// Catastrophic: still needs approval at "safe".
const CATASTROPHIC = [
  'mkfs.ext4 /dev/sdb1', 'sudo mkfs -t xfs /dev/nvme1n1', 'wipefs -a /dev/sdb', 'fdisk /dev/sda', 'parted /dev/sda mklabel gpt', 'sgdisk --zap-all /dev/sdb',
  'dd if=/dev/zero of=/dev/sda bs=1M', 'dd if=img.iso of=/dev/sdb', 'echo x > /dev/sda',
  'rm -rf /', 'rm -fr /*', 'sudo rm -rf --no-preserve-root /', 'rm -rf /etc', 'rm -rf /usr/', 'rm -rf /bin', 'rm -rf /boot', 'rm -rf /var', 'rm -rf /home', 'rm -rf /root',
  'rm -r -f /etc/*', 'cd /tmp && sudo rm -rf -- /var', 'rm -rf ~', 'rm -rf $HOME', 'find / -name "*" -delete',
  ':(){ :|:& };:', 'shutdown -h now', 'sudo poweroff', 'halt', 'systemctl poweroff', 'init 0',
  'sed -i s/no/yes/ /etc/ssh/sshd_config', "sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/50-cloud.conf",
  'echo ssh-ed25519 AAAA >> ~/.ssh/authorized_keys', 'rm ~/.ssh/authorized_keys && rm -rf /tmp/x', 'echo "deploy ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers',
  'ufw disable', 'ufw --force reset', 'iptables -F', 'iptables -P INPUT DROP', 'ip6tables -F', 'nft flush ruleset', 'systemctl stop ufw', 'systemctl disable --now sshd', 'service ssh stop',
  'mysql -e "DROP DATABASE prod"', 'psql -c "drop schema public cascade"',
  'docker system prune -a --volumes', 'docker system prune -af --volumes', 'docker volume rm pgdata', 'docker volume prune -f', 'docker compose down -v',
  'kill -9 1', 'kill -9 -1', 'chmod -R 777 /', 'chown -R nobody /',
];

describe('catastrophic list', () => {
  it.each(CATASTROPHIC)('catastrophic: %s', (c) => {
    expect(decide(c, MOD).action, 'must need confirmation in the first place').toBe('confirm');
    expect(cat(c).length, c).toBeGreaterThan(0);
  });
  it.each(SAFE_DESTRUCTIVE)('destructive but not catastrophic: %s', (c) => {
    expect(decide(c, MOD).action).toBe('confirm');
    expect(cat(c), c).toEqual([]);
  });
  it('does not mistake reads or harmless dd for catastrophic', () => {
    expect(cat('dd if=/dev/sda of=/dev/null bs=1M count=1')).toEqual([]);
    expect(cat('rm -rf /var/www')).toEqual([]);
    expect(cat('rm /etc/nginx/conf.d/old.conf')).toEqual([]);
  });
  it('detects system paths', () => {
    for (const p of ['/', '//', '/*', '/etc', '/etc/', '/etc/*', '/usr', '/home', '/root', '/var/', '~', '$HOME', "'/etc'"]) expect(isSystemPath(p), p).toBe(true);
    for (const p of ['/etc/nginx', '/var/www', '/home/deploy/app', '/tmp/x', 'etc', './var']) expect(isSystemPath(p), p).toBe(false);
  });
  it('delete_file catastrophic paths', () => {
    expect(catastrophicDeleteReasons('/etc', true).length).toBeGreaterThan(0);
    expect(catastrophicDeleteReasons('/home', false).length).toBeGreaterThan(0);
    expect(catastrophicDeleteReasons('/etc/ssh/sshd_config', false).length).toBeGreaterThan(0);
    expect(catastrophicDeleteReasons('/home/deploy/.ssh/authorized_keys', false).length).toBeGreaterThan(0);
    expect(catastrophicDeleteReasons('/etc/shadow', false).length).toBeGreaterThan(0);
    expect(catastrophicDeleteReasons('/tmp/file.txt', false)).toEqual([]);
    expect(catastrophicDeleteReasons('/var/www/old', true)).toEqual([]);
    expect(catastrophicDeleteReasons('/etc/nginx/sites-enabled/default', false)).toEqual([]);
  });
});

describe('auto-approve levels', () => {
  it('off never auto-approves', () => {
    for (const c of [...SAFE_DESTRUCTIVE, ...CATASTROPHIC]) expect(autoApproveCommand('off', c, decide(c, MOD)).auto).toBe(false);
  });
  it('safe auto-approves destructive but not catastrophic', () => {
    for (const c of SAFE_DESTRUCTIVE) {
      const r = autoApproveCommand('safe', c, decide(c, MOD));
      expect(r.auto, c).toBe(true);
      if (r.auto) expect(r.approval.level).toBe('safe');
    }
    for (const c of CATASTROPHIC) {
      const r = autoApproveCommand('safe', c, decide(c, MOD));
      expect(r.auto, c).toBe(false);
      if (!r.auto) expect(r.catastrophic.length).toBeGreaterThan(0);
    }
  });
  it('all auto-approves everything that would need confirmation', () => {
    for (const c of [...SAFE_DESTRUCTIVE, ...CATASTROPHIC]) {
      const r = autoApproveCommand('all', c, decide(c, MOD));
      expect(r.auto, c).toBe(true);
      if (r.auto) expect(r.approval.level).toBe('all');
    }
  });
  it('never overrides a block: read-only mode wins at every level', () => {
    for (const level of ['off', 'safe', 'all'] as const) {
      for (const c of ['rm -rf /tmp/x', 'touch /tmp/x', 'mkfs.ext4 /dev/sdb']) {
        const d = decide(c, RO);
        expect(d.action).toBe('block');
        expect(autoApproveCommand(level, c, d).auto).toBe(false);
      }
      const dd = decideOperation('destructive', 'delete /tmp/x', RO);
      expect(dd.action).toBe('block');
      expect(autoApproveDelete(level, '/tmp/x', false, dd).auto).toBe(false);
    }
  });
  it('sudo package install block is not overridden by "all"', () => {
    const d = decide('sudo apt-get install -y htop', MOD);
    expect(d.action).toBe('block');
    expect(autoApproveCommand('all', 'sudo apt-get install -y htop', d).auto).toBe(false);
  });
  it('allow decisions pass through untouched (nothing to approve)', () => {
    const d = decide('ls -la', MOD);
    expect(autoApprove('all', d, []).auto).toBe(false);
  });
  it('delete_file levels', () => {
    const d = decideOperation('destructive', 'delete /tmp/x', MOD);
    expect(autoApproveDelete('off', '/tmp/x', false, d).auto).toBe(false);
    expect(autoApproveDelete('safe', '/tmp/x', false, d).auto).toBe(true);
    expect(autoApproveDelete('safe', '/tmp/dir', true, d).auto).toBe(true);
    expect(autoApproveDelete('safe', '/etc/ssh/sshd_config', false, d).auto).toBe(false);
    expect(autoApproveDelete('safe', '/etc', true, d).auto).toBe(false);
    expect(autoApproveDelete('all', '/etc/ssh/sshd_config', false, d).auto).toBe(true);
  });
  it('normalizes unknown levels to off and validates the typed confirmation', () => {
    expect(normalizeLevel(undefined)).toBe('off');
    expect(normalizeLevel('ALL')).toBe('off');
    expect(normalizeLevel('safe')).toBe('safe');
    for (const ok of ['CONFIRM', 'confirm', ' Confirm ', 'تأیید', 'تایید', 'تأييد']) expect(isAllConfirmText(ok), ok).toBe(true);
    for (const bad of ['', 'yes', 'all', 'confirmx', undefined, 42]) expect(isAllConfirmText(bad), String(bad)).toBe(false);
  });
});

describe('policy additions', () => {
  it('iptables DROP default policy is destructive (needs confirmation at off)', () => {
    expect(classifyCommand('iptables -P INPUT DROP').classification).toBe('destructive');
    expect(classifyCommand('iptables -L -n').classification).toBe('read');
  });
});
