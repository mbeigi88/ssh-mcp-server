// Command classification + per-server execution policy.
//
// Classes:   read  < modify < destructive
// Policy:    read_only  -> only `read` runs; everything else is blocked
//            modify     -> `read` and `modify` run; `destructive` needs human confirmation
// sudo:      sudo package installs run only when allow_sudo_install is set (otherwise blocked);
//            any other sudo use is at least `modify`.
// This is a guard-rail, not a sandbox: an allowed shell can always do harm, so destructive
// detection is deliberately broad and unknown commands default to `modify`.

export type CommandClass = 'read' | 'modify' | 'destructive';

export interface Classification {
  classification: CommandClass;
  reasons: string[];
  usesSudo: boolean;
  packageInstall: boolean;
}

export interface ServerPolicy {
  policy_mode: 'read_only' | 'modify';
  allow_sudo_install: boolean;
}

export type PolicyDecision =
  | { action: 'allow'; classification: Classification }
  | { action: 'confirm'; classification: Classification; reason: string }
  | { action: 'block'; classification: Classification; reason: string };

const RANK: Record<CommandClass, number> = { read: 0, modify: 1, destructive: 2 };

interface Rule { re: RegExp; reason: string }

const DESTRUCTIVE: Rule[] = [
  { re: /\brm\s+(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)\b/, reason: 'recursive rm' },
  { re: /\brm\s+(?:-[A-Za-z]*\s+)*--no-preserve-root\b/, reason: 'rm --no-preserve-root' },
  { re: /\bmkfs(?:\.[a-z0-9]+)?\b/, reason: 'filesystem format (mkfs)' },
  { re: /\b(?:wipefs|fdisk|sfdisk|cfdisk|parted|sgdisk|gdisk|shred|blkdiscard)\b/, reason: 'disk partition/wipe tool' },
  { re: /\bdd\b[^|;&]*\bof=\/dev\//, reason: 'dd writing to a device' },
  { re: />\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-|mapper)/, reason: 'redirect onto a block device' },
  { re: /\bdrop\s+(?:database|schema|table)\b/i, reason: 'SQL DROP' },
  { re: /\btruncate\s+table\b/i, reason: 'SQL TRUNCATE' },
  { re: /\bufw\s+(?:--force\s+)?(?:disable|reset)\b/, reason: 'disables/resets ufw' },
  { re: /\biptables\b[^|;&]*(?:\s-F\b|--flush\b|\s-X\b|--delete-chain\b|\s-P\s+\w+\s+ACCEPT\b)/, reason: 'flushes iptables' },
  { re: /\bip6?tables\b[^|;&]*\s-P\s+(?:INPUT|OUTPUT|FORWARD)\s+(?:DROP|REJECT)\b/, reason: 'sets a DROP default firewall policy' },
  { re: /\bip6tables\b[^|;&]*(?:\s-F\b|--flush\b|\s-X\b)/, reason: 'flushes ip6tables' },
  { re: /\bnft\s+(?:flush|delete)\b/, reason: 'flushes nftables' },
  { re: /\bsystemctl\s+(?:stop|disable|mask|kill)\s+(?:[\w@.-]+\s+)*(?:ufw|firewalld|nftables|iptables|sshd?|ssh\.service|sshd\.service)\b/, reason: 'stops firewall/ssh service' },
  { re: /\bservice\s+(?:sshd?|ufw|firewalld|nftables|iptables)\s+stop\b/, reason: 'stops firewall/ssh service' },
  { re: /\bdocker\s+(?:volume\s+(?:rm|prune)|system\s+prune|container\s+prune|image\s+prune|network\s+prune|builder\s+prune)\b/, reason: 'docker prune/volume rm' },
  { re: /\bdocker\s+(?:rm|rmi)\s+(?:-[A-Za-z]*f|--force)\b/, reason: 'forced docker rm' },
  { re: /\bdocker\s+compose\s+down\b[^|;&]*(?:-v\b|--volumes\b)/, reason: 'docker compose down -v' },
  { re: /\b(?:shutdown|reboot|poweroff|halt)\b/, reason: 'shutdown/reboot' },
  { re: /\binit\s+[06]\b|\btelinit\s+[06]\b/, reason: 'runlevel change' },
  { re: /\bsystemctl\s+(?:reboot|poweroff|halt|kexec|emergency|rescue)\b/, reason: 'systemctl power action' },
  { re: /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:/, reason: 'fork bomb' },
  { re: /\b(?:userdel|deluser|groupdel|delgroup)\b/, reason: 'deletes users/groups' },
  { re: /\bcrontab\s+(?:-[a-z]*r)/, reason: 'removes crontab' },
  { re: /\bkill(?:all)?\s+(?:-9\s+|-KILL\s+|-s\s+KILL\s+)?(?:-1|1)\b(?!\d)/, reason: 'kills init/all processes' },
  { re: /\bfind\b[^|;&]*(?:-delete\b|-exec\s+rm\b)/, reason: 'find with delete' },
  { re: /\b(?:curl|wget)\b[^|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/, reason: 'pipes remote script into a shell' },
  { re: /\bchmod\s+(?:-[A-Za-z]*R[A-Za-z]*\s+)\S+\s+\/(?:\s|$)/, reason: 'recursive chmod on /' },
  { re: /\bchown\s+(?:-[A-Za-z]*R[A-Za-z]*\s+)\S+\s+\/(?:\s|$)/, reason: 'recursive chown on /' },
  { re: /\bmv\s+(?:-\w+\s+)*\/(?:\s|$)/, reason: 'moves /' },
  { re: />\s*\/(?:boot|etc)\//, reason: 'overwrites a system file' },
  { re: /\bswapoff\s+-a\b|\bumount\s+(?:-[a-z]+\s+)*\/(?:\s|$)/, reason: 'unmounts root/swap' },
];

// Sensitive files: reading them is fine, any other access (write, edit, copy over, delete) is destructive.
const SENSITIVE: Rule[] = [
  { re: /\bsshd_config\b|\/etc\/ssh\/sshd_config\.d\b/, reason: 'modifies sshd_config' },
  { re: /\bauthorized_keys2?\b/, reason: 'modifies authorized_keys' },
  { re: /\bsudoers\b/, reason: 'modifies sudoers' },
  { re: /\/etc\/(?:passwd|shadow|group|gshadow)\b/, reason: 'modifies the account database' },
];
const PURE_READERS = new Set(['cat', 'less', 'more', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'rg', 'stat', 'ls', 'wc', 'diff', 'cmp', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'file', 'getent', 'awk', 'cut', 'sort', 'uniq', 'test', '[', 'readlink', 'realpath', 'ssh-keygen']);
const DESTRUCTIVE_BINS: Record<string, string> = { passwd: 'changes a password', chpasswd: 'changes passwords', visudo: 'edits sudoers', usermod: 'modifies a user account', vipw: 'edits the account database' };

const READ_COMMANDS = new Set([
  'ls', 'll', 'cat', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'zgrep', 'rg', 'stat', 'df', 'du', 'free', 'uptime', 'uname',
  'whoami', 'id', 'hostname', 'hostnamectl', 'ps', 'pgrep', 'pstree', 'top', 'htop', 'journalctl', 'date', 'echo', 'printf',
  'pwd', 'which', 'whereis', 'type', 'file', 'wc', 'sort', 'uniq', 'cut', 'tr', 'less', 'more', 'nproc', 'lscpu', 'lsblk',
  'lsof', 'lspci', 'lsusb', 'lsmod', 'dmesg', 'last', 'lastlog', 'w', 'who', 'users', 'getent', 'dig', 'nslookup', 'host',
  'ping', 'traceroute', 'tracepath', 'mtr', 'ss', 'netstat', 'ifconfig', 'route', 'arp', 'env', 'printenv', 'test', '[',
  'true', 'false', 'sleep', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'basename', 'dirname', 'realpath', 'readlink',
  'tree', 'diff', 'cmp', 'column', 'jq', 'yq', 'awk', 'sed', 'xxd', 'od', 'hexdump', 'strings', 'vmstat', 'iostat', 'mpstat',
  'sar', 'nvidia-smi', 'sensors', 'timedatectl', 'localectl', 'loginctl', 'locale', 'groups', 'ulimit', 'getconf', 'seq',
  'find', 'mount', 'findmnt', 'blkid', 'cal', 'zcat', 'bzcat', 'xzcat', 'nl', 'fold', 'fmt', 'paste', 'join', 'comm', 'tac',
  'rev', 'expr', 'bc', 'exit', 'cd', 'export', 'set', 'unset', 'local', 'shift', 'wait', 'read', 'return', 'source', '.', ':', 'man', 'apropos', 'whatis', 'history', 'curl', 'wget', 'timeout', 'nice', 'time', 'watch', 'tput',
]);

const READ_SUBCOMMANDS: Record<string, RegExp> = {
  systemctl: /^(?:status|is-active|is-enabled|is-failed|list-units|list-unit-files|list-timers|list-sockets|show|cat|--version|--failed)\b/,
  docker: /^(?:ps|logs|inspect|images|image\s+ls|stats\s+--no-stream|version|info|top|port|diff|container\s+(?:ls|inspect|logs|top|port)|volume\s+(?:ls|inspect)|network\s+(?:ls|inspect)|compose\s+(?:ps|logs|config|ls))\b/,
  ip: /^(?:-\S+\s+)*(?:a|addr|address|l|link|r|route|n|neigh|neighbour|rule|-s)(?:\s+(?:show|list|ls))?\b|^$/,
  git: /^(?:status|log|diff|show|branch|remote|rev-parse|describe|tag\s*$|config\s+--get|ls-files)\b/,
  apt: /^(?:list|show|search|policy)\b/,
  'apt-cache': /^/,
  dpkg: /^(?:-l|-L|-s|--list|--status|--listfiles|-S)\b/,
  rpm: /^-q/,
  snap: /^(?:list|info|version)\b/,
  kubectl: /^(?:get|describe|logs|top|version|config\s+view|cluster-info)\b/,
  npm: /^(?:ls|list|view|outdated|-v|--version)\b/,
  node: /^(?:-v|--version)\b/,
  python3: /^(?:-V|--version)\b/,
  python: /^(?:-V|--version)\b/,
  nginx: /^-[tTvV]\b/,
  ufw: /^status\b/,
  iptables: /^(?:-L|-S|--list|-n\s+-L|-nL|-vnL|-nvL)/,
  service: /^\S+\s+status\b|^--status-all\b/,
  crontab: /^-l\b/,
  sudo: /^-l\b|^-v\b/,
};

const PKG_INSTALL = /^(?:apt|apt-get|aptitude|yum|dnf|zypper|apk|pacman|snap|pip3?|npm)\s+(?:-\S+\s+)*(?:install|add|-S\b|upgrade|update|dist-upgrade|full-upgrade|reinstall)\b/;

/** Splits a command line into simple-command segments on ; && || | & newline and $( ) / backticks. */
export function splitSegments(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  let sq = false;
  let dq = false;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (ch === '\\' && !sq && i + 1 < cmd.length) { cur += ch + cmd[++i]; continue; }
    if (ch === "'" && !dq) { sq = !sq; cur += ch; continue; }
    if (ch === '"' && !sq) { dq = !dq; cur += ch; continue; }
    if (!sq) {
      if (ch === '$' && cmd[i + 1] === '(') { out.push(cur); cur = ''; i++; continue; }
      if (ch === '`' || (ch === ')' && !dq)) { out.push(cur); cur = ''; continue; }
    }
    if (!sq && !dq) {
      // keep redirections like 2>&1, >&2, &>file intact
      if (ch === '&' && (cmd[i - 1] === '>' || cmd[i - 1] === '<' || cmd[i + 1] === '>')) { cur += ch; continue; }
      if (ch === ';' || ch === '\n' || ch === '|' || ch === '&') { out.push(cur); cur = ''; continue; }
    }
    cur += ch;
  }
  out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

function stripPrefixes(seg: string): { seg: string; sudo: boolean } {
  let s = seg.trim();
  let sudo = false;
  for (let guard = 0; guard < 10; guard++) {
    s = s.replace(/^\(+\s*/, '').replace(/^\{\s*/, '');
    const m = /^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S*)\s+)/.exec(s);
    if (m) { s = s.slice(m[0].length); continue; }
    const p = /^(sudo|doas|command|builtin|exec|nohup|nice|ionice|stdbuf|time|timeout|env|xargs|then|do|else|if|while|until|!)\b\s*/.exec(s);
    if (p) {
      if (p[1] === 'sudo' || p[1] === 'doas') {
        sudo = true;
        s = s.slice(p[0].length);
        s = s.replace(/^(?:-(?:[A-Za-z]+|-[\w-]+)(?:\s+(?!-)\S+)?\s+)*/, (flags) => (/-[ug]\s|--user/.test(flags) ? flags.replace(/.*/, '') : ''));
        continue;
      }
      if (p[1] === 'timeout') { s = s.slice(p[0].length).replace(/^(?:-\S+\s+)*\S+\s+/, ''); continue; }
      if (p[1] === 'nice' || p[1] === 'ionice') { s = s.slice(p[0].length).replace(/^(?:-\S+\s+(?:\d+\s+)?)*/, ''); continue; }
      s = s.slice(p[0].length);
      continue;
    }
    break;
  }
  return { seg: s, sudo };
}

function hasWriteRedirect(seg: string): boolean {
  // strip quoted strings first
  const s = seg.replace(/'[^']*'/g, "''").replace(/"(?:\\.|[^"\\])*"/g, '""');
  const re = /(\d*)>>?\s*(&?\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    const target = m[2];
    if (target.startsWith('&')) continue; // fd duplication like 2>&1
    if (target === '/dev/null' || target === '/dev/stdout' || target === '/dev/stderr') continue;
    return true;
  }
  return false;
}

export function classifyCommand(command: string): Classification {
  const reasons: string[] = [];
  let cls: CommandClass = 'read';
  let usesSudo = false;
  let packageInstall = false;
  const bump = (c: CommandClass, why: string) => {
    if (RANK[c] > RANK[cls]) cls = c;
    if (c !== 'read') reasons.push(why);
  };

  const normalized = command.replace(/\\\n/g, ' ');
  for (const r of DESTRUCTIVE) {
    if (r.re.test(normalized)) bump('destructive', r.reason);
  }
  // read-only views of sensitive files are fine: downgrade only if every matching segment is a pure reader
  for (const raw of splitSegments(normalized)) {
    const { seg, sudo } = stripPrefixes(raw);
    if (sudo) usesSudo = true;
    if (!seg) continue;
    const words = seg.split(/\s+/);
    const bin = words[0].replace(/^.*\//, '');
    const rest = seg.slice(words[0].length).trim();
    if (DESTRUCTIVE_BINS[bin]) bump('destructive', DESTRUCTIVE_BINS[bin]);
    for (const r of SENSITIVE) {
      if (r.re.test(seg) && (!PURE_READERS.has(bin) || hasWriteRedirect(seg) || (bin === 'awk' && /system\s*\(|>/.test(rest)))) bump('destructive', r.reason);
    }
    if (PKG_INSTALL.test(`${bin} ${rest}`)) {
      packageInstall = true;
      bump('modify', `package management (${bin})`);
      continue;
    }
    if (hasWriteRedirect(seg)) bump('modify', 'writes via shell redirection');
    if (bin === 'tee') { bump('modify', 'tee writes files'); continue; }
    if (bin === 'sed' && /(?:^|\s)-[A-Za-z]*i|--in-place/.test(rest)) { bump('modify', 'sed -i edits files'); continue; }
    if (bin === 'awk' && /system\s*\(|>\s*"/.test(rest)) { bump('modify', 'awk with side effects'); continue; }
    if ((bin === 'curl' && /(?:^|\s)(?:-o|-O|--output|--remote-name|-T|--upload-file|-d|--data|-X\s*(?:POST|PUT|DELETE|PATCH))\b/.test(rest)) ||
        (bin === 'wget' && !/(?:^|\s)(?:-O\s*-|-qO-|--spider)\b/.test(rest))) {
      bump('modify', `${bin} may write files or mutate remote state`);
      continue;
    }
    if (bin === 'find' && /(?:-exec|-execdir|-ok|-delete|-fprint)/.test(rest)) { bump('modify', 'find with actions'); continue; }
    if (READ_SUBCOMMANDS[bin]) {
      if (READ_SUBCOMMANDS[bin].test(rest)) continue;
      bump('modify', `${bin} ${rest.split(/\s+/)[0] ?? ''}`.trim());
      continue;
    }
    if (READ_COMMANDS.has(bin)) continue;
    if (/^(?:for|case|esac|done|fi|in|function|select)$/.test(bin) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(bin)) continue;
    bump('modify', `unrecognized or mutating command: ${bin}`);
  }
  if (usesSudo && cls === 'read') bump('modify', 'uses sudo');
  return { classification: cls, reasons: Array.from(new Set(reasons)), usesSudo, packageInstall };
}

export function decide(command: string, policy: ServerPolicy): PolicyDecision {
  const c = classifyCommand(command);
  if (c.usesSudo && c.packageInstall && !policy.allow_sudo_install) {
    return { action: 'block', classification: c, reason: 'sudo package installation is disabled for this server (enable "allow sudo package installs")' };
  }
  if (policy.policy_mode === 'read_only' && c.classification !== 'read') {
    return { action: 'block', classification: c, reason: `server is in read-only mode; command classified as ${c.classification} (${c.reasons.join('; ')})` };
  }
  if (c.classification === 'destructive') {
    return { action: 'confirm', classification: c, reason: c.reasons.join('; ') };
  }
  return { action: 'allow', classification: c };
}

/** Policy for non-shell tools (SFTP, etc.). */
export function decideOperation(kind: CommandClass, what: string, policy: ServerPolicy): PolicyDecision {
  const c: Classification = { classification: kind, reasons: kind === 'read' ? [] : [what], usesSudo: false, packageInstall: false };
  if (policy.policy_mode === 'read_only' && kind !== 'read') return { action: 'block', classification: c, reason: `server is in read-only mode (${what})` };
  if (kind === 'destructive') return { action: 'confirm', classification: c, reason: what };
  return { action: 'allow', classification: c };
}
