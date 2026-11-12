import type { Env } from '../env';
import { KeyRing, randomId } from './crypto';
import { normalizeLevel, type AutoApproveLevel } from './auto-approve';

export interface ServerRow {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_method: 'password' | 'key';
  cred_ciphertext: string | null;
  cred_iv: string | null;
  cred_key_version: number;
  has_password: number;
  has_private_key: number;
  has_passphrase: number;
  host_key_fingerprint: string | null;
  host_key_algo: string | null;
  pending_fingerprint: string | null;
  pending_fingerprint_algo: string | null;
  labels: string;
  is_default: number;
  allow_root: number;
  policy_mode: 'read_only' | 'modify';
  allow_sudo_install: number;
  auto_approve: AutoApproveLevel;
  status: string;
  last_error: string | null;
  last_connected_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface Credentials {
  password?: string;
  privateKey?: string;
  passphrase?: string;
}

/** Public, secret-free view of a server. This is the ONLY shape that leaves the backend. */
export interface PublicServer {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_method: 'password' | 'key';
  password: 'set' | 'unset';
  private_key: 'set' | 'unset';
  passphrase: 'set' | 'unset';
  host_key_fingerprint: string | null;
  host_key_algo: string | null;
  pending_fingerprint: string | null;
  pending_fingerprint_algo: string | null;
  labels: string[];
  is_default: boolean;
  allow_root: boolean;
  policy_mode: 'read_only' | 'modify';
  allow_sudo_install: boolean;
  auto_approve: AutoApproveLevel;
  status: string;
  last_error: string | null;
  last_connected_at: number | null;
  created_at: number;
  updated_at: number;
}

export function toPublic(r: ServerRow): PublicServer {
  let labels: string[] = [];
  try { labels = JSON.parse(r.labels); } catch { labels = []; }
  return {
    id: r.id,
    name: r.name,
    host: r.host,
    port: r.port,
    username: r.username,
    auth_method: r.auth_method,
    password: r.has_password ? 'set' : 'unset',
    private_key: r.has_private_key ? 'set' : 'unset',
    passphrase: r.has_passphrase ? 'set' : 'unset',
    host_key_fingerprint: r.host_key_fingerprint,
    host_key_algo: r.host_key_algo,
    pending_fingerprint: r.pending_fingerprint,
    pending_fingerprint_algo: r.pending_fingerprint_algo,
    labels,
    is_default: !!r.is_default,
    allow_root: !!r.allow_root,
    policy_mode: r.policy_mode,
    allow_sudo_install: !!r.allow_sudo_install,
    auto_approve: normalizeLevel(r.auto_approve),
    status: r.status,
    last_error: r.last_error,
    last_connected_at: r.last_connected_at,
    created_at: r.created_at,
    updated_at: r.updated_at,
  };
}

export async function getServer(env: Env, id: string): Promise<ServerRow | null> {
  return env.DB.prepare('SELECT * FROM servers WHERE id = ?').bind(id).first<ServerRow>();
}

export async function listServers(env: Env): Promise<ServerRow[]> {
  const r = await env.DB.prepare('SELECT * FROM servers ORDER BY is_default DESC, name ASC').all<ServerRow>();
  return r.results ?? [];
}

/** Resolve by id or name; when ref is empty, return the default server. */
export async function resolveServer(env: Env, ref?: string | null): Promise<ServerRow> {
  let row: ServerRow | null;
  if (ref && ref.trim()) {
    row = await env.DB.prepare('SELECT * FROM servers WHERE id = ?1 OR name = ?1 LIMIT 1').bind(ref.trim()).first<ServerRow>();
    if (!row) throw new UserError(`server "${ref}" not found`);
  } else {
    row = await env.DB.prepare('SELECT * FROM servers WHERE is_default = 1 LIMIT 1').first<ServerRow>();
    if (!row) {
      const all = await listServers(env);
      if (all.length === 1) row = all[0];
      else throw new UserError(all.length === 0 ? 'no servers configured' : 'no default server set; pass the "server" argument');
    }
  }
  return row;
}

export async function encryptCredentials(env: Env, serverId: string, creds: Credentials) {
  const ring = KeyRing.fromEnv(env);
  return ring.encrypt(JSON.stringify(creds), `server:${serverId}`);
}

export async function decryptCredentials(env: Env, row: ServerRow): Promise<Credentials> {
  if (!row.cred_ciphertext || !row.cred_iv) return {};
  const ring = KeyRing.fromEnv(env);
  const json = await ring.decrypt({ ciphertext: row.cred_ciphertext, iv: row.cred_iv, keyVersion: row.cred_key_version }, `server:${row.id}`);
  return JSON.parse(json) as Credentials;
}

export class UserError extends Error {
  status: number;
  constructor(msg: string, status = 400) { super(msg); this.name = 'UserError'; this.status = status; }
}

// ---------------- settings ----------------

export interface Settings {
  allow_private_targets: boolean;
  idle_timeout_seconds: number;
  default_command_timeout_seconds: number;
  max_output_bytes: number;
  confirmation_ttl_seconds: number;
  session_ttl_hours: number;
  /** auto-approve level given to newly created servers */
  default_auto_approve: AutoApproveLevel;
}

export const DEFAULT_SETTINGS: Settings = {
  allow_private_targets: false,
  idle_timeout_seconds: 300,
  default_command_timeout_seconds: 60,
  max_output_bytes: 256 * 1024,
  confirmation_ttl_seconds: 900,
  session_ttl_hours: 12,
  default_auto_approve: 'off',
};

export async function getSettings(env: Env): Promise<Settings> {
  const r = await env.DB.prepare("SELECT key, value FROM settings WHERE key NOT LIKE 'secret:%'").all<{ key: string; value: string }>();
  const s: Settings = { ...DEFAULT_SETTINGS };
  for (const row of r.results ?? []) {
    if (row.key in s) {
      try { (s as unknown as Record<string, unknown>)[row.key] = JSON.parse(row.value); } catch { /* ignore */ }
    }
  }
  s.default_auto_approve = normalizeLevel(s.default_auto_approve);
  return s;
}

export async function putSettings(env: Env, patch: Partial<Settings>): Promise<void> {
  const now = Date.now();
  const stmts = Object.entries(patch)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) =>
      env.DB.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').bind(k, JSON.stringify(v), now),
    );
  if (stmts.length) await env.DB.batch(stmts);
}

export async function getSecretSetting(env: Env, key: string): Promise<string | null> {
  const r = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(`secret:${key}`).first<{ value: string }>();
  return r?.value ?? null;
}
export async function putSecretSetting(env: Env, key: string, value: string): Promise<void> {
  await env.DB.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at')
    .bind(`secret:${key}`, value, Date.now())
    .run();
}

export function allowPrivateTargets(env: Env, s: Settings): boolean {
  return env.DEV_ALLOW_PRIVATE_TARGETS === 'true' || s.allow_private_targets;
}

// ---------------- audit ----------------

export async function audit(
  env: Env,
  entry: { actor: string; action: string; server_id?: string | null; outcome?: string; detail?: unknown; ip?: string | null; auto_level?: AutoApproveLevel | null },
): Promise<void> {
  try {
    const auto = entry.auto_level && entry.auto_level !== 'off' ? entry.auto_level : null;
    await env.DB.prepare('INSERT INTO audit_log (ts, actor, action, server_id, outcome, detail, ip, auto_approved, auto_level) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(Date.now(), entry.actor, entry.action, entry.server_id ?? null, entry.outcome ?? 'ok', entry.detail === undefined ? null : JSON.stringify(redact(entry.detail)).slice(0, 4000), entry.ip ?? null, auto ? 1 : 0, auto)
      .run();
  } catch (e) {
    console.error('audit write failed', (e as Error).message);
  }
}

const SECRET_KEYS = /pass(word|phrase)?|private_?key|secret|token|authorization|cookie|credential/i;
/** Deep-redacts anything that looks like a secret before it is logged anywhere. */
export function redact(v: unknown, depth = 0): unknown {
  if (depth > 6) return '[depth]';
  if (Array.isArray(v)) return v.map((x) => redact(x, depth + 1));
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out[k] = SECRET_KEYS.test(k) && !/^(has_|.*_set$)/.test(k) ? '[redacted]' : redact(val, depth + 1);
    }
    return out;
  }
  if (typeof v === 'string' && /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(v)) return '[redacted private key]';
  return v;
}

export async function recordConnectionEvent(env: Env, serverId: string, event: string, detail?: string, durationMs?: number) {
  try {
    await env.DB.prepare('INSERT INTO connection_history (server_id, ts, event, detail, duration_ms) VALUES (?, ?, ?, ?, ?)')
      .bind(serverId, Date.now(), event, detail ? detail.slice(0, 1000) : null, durationMs ?? null)
      .run();
  } catch (e) {
    console.error('connection_history write failed', (e as Error).message);
  }
}

export { randomId };
