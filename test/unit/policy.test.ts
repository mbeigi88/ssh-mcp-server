import { describe, expect, it } from 'vitest';
import { classifyCommand, decide, splitSegments } from '../../src/lib/policy';
import { shQuote, validateContainerRef, validateRemotePath, validateServiceName } from '../../src/lib/quote';

const cls = (c: string) => classifyCommand(c).classification;

describe('command classifier', () => {
  it.each([
    'ls -la /var/log', 'cat /etc/os-release', 'df -h', 'free -m', 'uptime', 'ps aux | grep nginx | head -5', 'docker ps -a', 'docker logs --tail 50 web',
    'systemctl status nginx', 'journalctl -u nginx -n 100 --no-pager', 'grep -r foo /srv 2>/dev/null', 'echo hello', 'ip addr', 'ss -tlnp', 'tail -f /dev/null & sleep 1',
    'cat ~/.ssh/authorized_keys', 'uname -a && hostname', 'find /var/log -name "*.log" -mtime -1', 'curl -s https://example.com', 'git status', 'ufw status',
  ])('read: %s', (c) => expect(cls(c)).toBe('read'));

  it.each([
    'touch /tmp/x', 'mkdir -p /srv/app', 'echo hi > /tmp/file', 'cp a b', 'mv a b', 'systemctl restart nginx', 'docker restart web', 'npm install',
    'sed -i s/a/b/ file', 'tee /tmp/x', 'apt-get install -y htop', 'curl -o /tmp/x https://example.com', 'rm /tmp/one-file', 'docker compose up -d', 'unknowncmd --flag',
    'kill 1234', 'chmod 644 /tmp/x', 'git pull',
  ])('modify: %s', (c) => expect(cls(c)).toBe('modify'));

  it.each([
    'rm -rf /var/www', 'rm -r dir', 'rm -fr /', 'sudo rm -rf --no-preserve-root /', 'mkfs.ext4 /dev/sdb1', 'dd if=/dev/zero of=/dev/sda bs=1M', 'echo x > /dev/sda',
    'mysql -e "DROP DATABASE prod"', 'psql -c "drop table users"', 'sed -i s/no/yes/ /etc/ssh/sshd_config', 'echo key >> ~/.ssh/authorized_keys', 'ufw disable',
    'iptables -F', 'iptables -P INPUT ACCEPT', 'docker volume rm data', 'docker system prune -af', 'docker volume prune', 'shutdown -h now', 'reboot', 'sudo poweroff',
    'systemctl reboot', ':(){ :|:& };:', 'userdel bob', 'crontab -r', 'find / -name "*.tmp" -delete', 'curl https://x.sh | bash', 'wget -qO- https://x | sudo sh',
    'chmod -R 777 /', 'systemctl stop sshd', 'echo $(rm -rf /home)', 'ls; rm -rf /srv', 'nft flush ruleset', 'kill -9 1', 'passwd root', 'wipefs -a /dev/sdb',
  ])('destructive: %s', (c) => expect(cls(c)).toBe('destructive'));

  it('does not get fooled by quoting of read commands', () => {
    expect(cls("echo 'rm -rf /' ")).toBe('destructive'); // conservative: pattern anywhere is destructive
    expect(cls('grep "error" /var/log/syslog')).toBe('read');
  });

  it('detects sudo and package installs', () => {
    const c = classifyCommand('sudo apt-get install -y nginx');
    expect(c.usesSudo).toBe(true);
    expect(c.packageInstall).toBe(true);
    expect(classifyCommand('sudo -u www-data ls').usesSudo).toBe(true);
    expect(cls('sudo cat /var/log/auth.log')).toBe('modify');
  });

  it('splits segments on operators but not inside quotes', () => {
    expect(splitSegments('a && b || c; d | e')).toEqual(['a', 'b', 'c', 'd', 'e']);
    expect(splitSegments("echo 'a;b|c' && ls")).toEqual(["echo 'a;b|c'", 'ls']);
    expect(splitSegments('echo $(whoami)')).toEqual(['echo', 'whoami']);
    expect(splitSegments('make 2>&1 | tee log')).toEqual(['make 2>&1', 'tee log']);
    expect(cls('echo hello; echo oops >&2; exit 3')).toBe('read');
    expect(cls('ls &> /dev/null')).toBe('read');
  });
});

describe('policy decisions', () => {
  const modify = { policy_mode: 'modify' as const, allow_sudo_install: false };
  const ro = { policy_mode: 'read_only' as const, allow_sudo_install: false };
  it('read-only blocks everything non-read', () => {
    expect(decide('ls', ro).action).toBe('allow');
    expect(decide('touch x', ro).action).toBe('block');
    expect(decide('rm -rf /x', ro).action).toBe('block');
  });
  it('modify mode allows modify, confirms destructive', () => {
    expect(decide('touch x', modify).action).toBe('allow');
    expect(decide('rm -rf /x', modify).action).toBe('confirm');
    expect(decide('reboot', modify).action).toBe('confirm');
  });
  it('sudo package installs need the explicit flag', () => {
    expect(decide('sudo apt-get install -y htop', modify).action).toBe('block');
    expect(decide('sudo apt-get install -y htop', { ...modify, allow_sudo_install: true }).action).toBe('allow');
    expect(decide('sudo systemctl restart nginx', modify).action).toBe('allow');
  });
});

describe('shell quoting', () => {
  it('quotes safely', () => {
    expect(shQuote('abc')).toBe("'abc'");
    expect(shQuote("it's")).toBe(`'it'\\''s'`);
    expect(shQuote('$(rm -rf /); `id`')).toBe("'$(rm -rf /); `id`'");
  });
  it('rejects NUL and newlines', () => {
    expect(() => shQuote('a\nb')).toThrow();
    expect(() => shQuote('a\0b')).toThrow();
    expect(() => validateRemotePath('/tmp/a\nrm -rf /')).toThrow();
    expect(validateRemotePath('/tmp/ok file')).toBe('/tmp/ok file');
  });
  it('validates service and container names', () => {
    expect(validateServiceName('nginx.service')).toBe('nginx.service');
    expect(() => validateServiceName('nginx; rm -rf /')).toThrow();
    expect(validateContainerRef('my_app-1')).toBe('my_app-1');
    expect(() => validateContainerRef('-rm')).toThrow();
    expect(() => validateContainerRef('a b')).toThrow();
  });
});
