// Auto-approve: per-server opt-in to skip the human confirmation step for destructive operations.
//
//   off  -> unchanged: every destructive operation needs a human (default)
//   safe -> destructive operations run immediately EXCEPT the hard "catastrophic" list below
//   all  -> every destructive operation runs immediately
//
// Auto-approve only ever turns a `confirm` decision into `allow`. It never overrides a `block`
// (read-only mode, disabled sudo installs, refused system-directory deletes), so read-only
// servers stay read-only regardless of the level.
import { splitSegments, type PolicyDecision } from './policy';

export type AutoApproveLevel = 'off' | 'safe' | 'all';
export const AUTO_APPROVE_LEVELS: readonly AutoApproveLevel[] = ['off', 'safe', 'all'] as const;

export function normalizeLevel(v: unknown): AutoApproveLevel {
  return v === 'safe' || v === 'all' ? v : 'off';
}

interface Rule { re: RegExp; reason: string }

// Top-level directories whose recursive removal destroys the system (or every user's data).
const SYSTEM_DIRS = ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib32', 'lib64', 'libx32', 'opt', 'proc', 'root', 'sbin', 'srv', 'sys', 'usr', 'var'];
const SYSTEM_DIR_RE = new RegExp(`^/+(?:(?:${SYSTEM_DIRS.join('|')})/*)?(?:\\*|\\.\\*)?$`);

/** True for "/", "/*", "/etc", "/etc/", "/etc/*", "~", "$HOME" … (after quote stripping). */
export function isSystemPath(p: string): boolean {
  const s = p.replace(/^['"]|['"]$/g, '').trim();
  if (!s) return false;
  if (/^(?:~|\$HOME|\$\{HOME\})\/*\*?$/.test(s)) return true;
  return SYSTEM_DIR_RE.test(s);
}

const CATASTROPHIC: Rule[] = [
  { re: /\bmkfs(?:\.[a-z0-9]+)?\b/, reason: 'formats a filesystem (mkfs)' },
  { re: /\b(?:wipefs|fdisk|sfdisk|cfdisk|parted|sgdisk|gdisk|blkdiscard|shred)\b(?![^|;&]*\s(?:-l\b|--list\b|print\b))[^|;&]*\/dev\//, reason: 'partitions/wipes a disk device' },
  { re: /\bdd\b[^|;&]*\bof=\/dev\/(?!null\b|zero\b|stdout\b|stderr\b)/, reason: 'dd writes to a device' },
  { re: />\s*\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-|mapper)/, reason: 'redirect onto a block device' },
  { re: /\brm\b[^|;&]*--no-preserve-root\b/, reason: 'rm --no-preserve-root' },
  { re: /:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:/, reason: 'fork bomb' },
  { re: /\b(?:shutdown|poweroff|halt)\b/, reason: 'shuts the server down' },
  { re: /\bsystemctl\s+(?:poweroff|halt|kexec|emergency|rescue)\b|\b(?:tel)?init\s+0\b/, reason: 'shuts the server down' },
  { re: /\bPasswordAuthentication\b|\bPermitRootLogin\b|\bPubkeyAuthentication\b/, reason: 'changes SSH authentication settings' },
  { re: /\bufw\s+(?:--force\s+)?(?:disable|reset)\b/, reason: 'disables the firewall (ufw)' },
  { re: /\b(?:ip6?tables)\b[^|;&]*(?:\s-F\b|--flush\b|\s-X\b|--delete-chain\b|\s-P\s+\w+\s+(?:ACCEPT|DROP|REJECT)\b)/, reason: 'flushes firewall rules / changes default policy' },
  { re: /\bnft\s+(?:flush|delete)\b/, reason: 'flushes nftables' },
  { re: /\bsystemctl\s+(?:stop|disable|mask|kill)\s+(?:[\w@.-]+\s+)*(?:ufw|firewalld|nftables|iptables|sshd?|ssh\.service|sshd\.service|ssh\.socket)\b/, reason: 'stops the firewall or SSH service' },
  { re: /\bservice\s+(?:sshd?|ufw|firewalld)\s+stop\b/, reason: 'stops the firewall or SSH service' },
  { re: /\bdrop\s+(?:database|schema)\b/i, reason: 'SQL DROP DATABASE' },
  { re: /\bdocker\s+volume\s+(?:rm|remove|prune)\b/, reason: 'deletes docker volumes' },
  { re: /\bdocker\s+system\s+prune\b[^|;&]*--volumes\b/, reason: 'docker system prune --volumes' },
  { re: /\bdocker(?:-|\s+)compose\s+down\b[^|;&]*(?:\s-v\b|--volumes\b)/, reason: 'docker compose down --volumes' },
  { re: /\bkill(?:all)?\s+(?:-9\s+|-KILL\s+|-s\s+KILL\s+)?(?:-1|1)\b(?!\d)/, reason: 'kills init / all processes' },
  { re: /\bch(?:mod|own)\s+(?:-[A-Za-z]*R[A-Za-z]*\s+)\S+\s+\/(?:\s|$)/, reason: 'recursive chmod/chown on /' },
  { re: /\bmv\s+(?:-\w+\s+)*\/(?:\s|$)/, reason: 'moves /' },
];

// Lock-out files: any non-read change counts. The classifier already marks such access as
// destructive with these reasons, so we match on its reasons instead of re-parsing.
const CATASTROPHIC_REASONS: Record<string, string> = {
  'modifies sshd_config': 'changes sshd_config',
  'modifies authorized_keys': 'changes authorized_keys',
  'modifies sudoers': 'changes sudoers',
  'modifies the account database': 'changes /etc/passwd|shadow|group',
};

const RM_RECURSIVE = /^-(?:[A-Za-z]*[rR][A-Za-z]*)$|^--recursive$/;

function stripLead(seg: string): string {
  let s = seg.trim();
  for (let i = 0; i < 6; i++) {
    const m = /^(?:\(+\s*|\{\s*|[A-Za-z_]\w*=\S*\s+|(?:sudo|doas|command|exec|nohup|nice|ionice|time|env|xargs|then|do|else|!)\b(?:\s+-\S+)*\s*)/.exec(s);
    if (!m || !m[0]) break;
    s = s.slice(m[0].length);
  }
  return s;
}

function rmTargetsSystem(seg: string): string | null {
  const s = stripLead(seg);
  const words = s.split(/\s+/).filter(Boolean);
  if (!words.length || words[0].replace(/^.*\//, '') !== 'rm') return null;
  let recursive = false;
  let endOpts = false;
  const targets: string[] = [];
  for (const w of words.slice(1)) {
    if (!endOpts && w === '--') { endOpts = true; continue; }
    if (!endOpts && w.startsWith('-')) { if (RM_RECURSIVE.test(w)) recursive = true; continue; }
    targets.push(w);
  }
  if (!recursive) return null;
  const hit = targets.find(isSystemPath);
  return hit ? `rm -r of a system directory (${hit.replace(/^['"]|['"]$/g, '')})` : null;
}

function findDeletesSystem(seg: string): string | null {
  const s = stripLead(seg);
  const m = /^find\s+(\S+)/.exec(s);
  if (!m || !/(?:-delete\b|-exec\s+rm\b)/.test(s)) return null;
  return isSystemPath(m[1]) ? `find -delete on a system directory (${m[1]})` : null;
}

/** Reasons a shell command is catastrophic (empty array when it is not). */
export function catastrophicReasons(command: string, classifierReasons: string[] = []): string[] {
  const out: string[] = [];
  const normalized = command.replace(/\\\n/g, ' ');
  for (const r of CATASTROPHIC) if (r.re.test(normalized)) out.push(r.reason);
  for (const seg of splitSegments(normalized)) {
    const a = rmTargetsSystem(seg);
    if (a) out.push(a);
    const b = findDeletesSystem(seg);
    if (b) out.push(b);
  }
  for (const r of classifierReasons) if (CATASTROPHIC_REASONS[r]) out.push(CATASTROPHIC_REASONS[r]);
  return Array.from(new Set(out));
}

const SENSITIVE_FILE = /(?:^|\/)(?:sshd_config|authorized_keys2?|sudoers)(?:$|\/)|\/etc\/ssh\/sshd_config\.d(?:$|\/)|\/etc\/sudoers\.d(?:$|\/)|^\/+etc\/+(?:passwd|shadow|group|gshadow)$/;

/** Reasons a delete_file operation is catastrophic. */
export function catastrophicDeleteReasons(path: string, recursive: boolean): string[] {
  const out: string[] = [];
  if (isSystemPath(path)) out.push(`${recursive ? 'recursive ' : ''}delete of a system directory (${path})`);
  if (SENSITIVE_FILE.test(path)) out.push(`deletes a lock-out critical file (${path})`);
  return out;
}

export interface AutoApproval {
  /** level that approved it */
  level: AutoApproveLevel;
  /** why it needed approval in the first place */
  reason: string;
}

export type AutoResult =
  | { auto: true; approval: AutoApproval }
  | { auto: false; catastrophic: string[] };

/**
 * Decides whether a `confirm` decision is auto-approved.
 * `catastrophic` must be computed by the caller (command or delete variant).
 */
export function autoApprove(level: AutoApproveLevel, decision: PolicyDecision, catastrophic: string[]): AutoResult {
  if (decision.action !== 'confirm') return { auto: false, catastrophic: [] };
  if (level === 'all') return { auto: true, approval: { level, reason: decision.reason } };
  if (level === 'safe' && catastrophic.length === 0) return { auto: true, approval: { level, reason: decision.reason } };
  return { auto: false, catastrophic };
}

/** Convenience for shell commands. */
export function autoApproveCommand(level: AutoApproveLevel, command: string, decision: PolicyDecision): AutoResult {
  if (decision.action !== 'confirm') return { auto: false, catastrophic: [] };
  return autoApprove(level, decision, catastrophicReasons(command, decision.classification.reasons));
}

/** Convenience for delete_file. */
export function autoApproveDelete(level: AutoApproveLevel, path: string, recursive: boolean, decision: PolicyDecision): AutoResult {
  if (decision.action !== 'confirm') return { auto: false, catastrophic: [] };
  return autoApprove(level, decision, catastrophicDeleteReasons(path, recursive));
}

/** Typed confirmation accepted by the dashboard before enabling "all". */
export function isAllConfirmText(s: unknown): boolean {
  if (typeof s !== 'string') return false;
  const v = s.trim().replace(/\u064A/g, '\u06CC').replace(/\u0643/g, '\u06A9');
  return /^confirm$/i.test(v) || v === 'تأیید' || v === 'تایید';
}
