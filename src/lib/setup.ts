// First-run admin setup.
// A fresh deployment has no admin password. Instead of a login form the dashboard then offers
// "Create admin password", which is only accepted together with SETUP_TOKEN — a secret the installer
// chose in the deploy form — so nobody who merely finds the URL of a fresh deployment can claim it.
// Once a password exists (or setup completed once) the endpoint is permanently disabled.
import type { Env } from '../env';
import { getSecretSetting } from './db';
import { adminPassword, LOCAL_PW_KEY } from './auth';
import { sha256Hex, timingSafeEqualStr } from './crypto';

export const SETUP_DONE_KEY = 'setup_completed_at';
export const MIN_SETUP_TOKEN_LENGTH = 12;
export const MIN_ADMIN_PASSWORD_LENGTH = 12;

export type SetupState =
  | 'done'            // an admin password exists -> normal login
  | 'available'       // no password, valid SETUP_TOKEN -> show "Create admin password"
  | 'needs_token'     // no password and no usable SETUP_TOKEN -> show instructions
  | 'locked'          // setup already used once but no password any more -> set ADMIN_PASSWORD_HASH
  | 'not_applicable'; // AUTH_MODE=access (Cloudflare Access only)

export function setupTokenProblem(v: string | undefined): 'missing' | 'too_short' | 'too_weak' | null {
  const t = (v ?? '').trim();
  if (!t) return 'missing';
  if (t.length < MIN_SETUP_TOKEN_LENGTH) return 'too_short';
  if (new Set(t).size < 5) return 'too_weak';
  return null;
}

export async function setupState(env: Env, mode: 'password' | 'access' | 'both'): Promise<{ state: SetupState; reason?: string }> {
  if (mode === 'access') return { state: 'not_applicable' };
  if (await adminPassword(env)) return { state: 'done' };
  if (await getSecretSetting(env, SETUP_DONE_KEY)) return { state: 'locked' };
  const p = setupTokenProblem(env.SETUP_TOKEN);
  if (p) return { state: 'needs_token', reason: `setup_token_${p}` };
  return { state: 'available' };
}

/** Constant-time comparison that does not leak the token length (compares SHA-256 digests). */
export async function setupTokenMatches(env: Env, candidate: string): Promise<boolean> {
  const expected = (env.SETUP_TOKEN ?? '').trim();
  if (!expected) return false;
  const [a, b] = await Promise.all([sha256Hex(candidate.trim()), sha256Hex(expected)]);
  return timingSafeEqualStr(a, b);
}

export function passwordProblem(pw: string, env: Env): string | null {
  if (pw.length < MIN_ADMIN_PASSWORD_LENGTH) return `password must be at least ${MIN_ADMIN_PASSWORD_LENGTH} characters`;
  if (pw.length > 1024) return 'password is too long';
  if (new Set(pw).size < 5) return 'password is too simple (use more different characters)';
  if (env.SETUP_TOKEN && pw.trim() === env.SETUP_TOKEN.trim()) return 'the admin password must be different from the setup token';
  return null;
}

/**
 * Atomically stores the first admin password. Returns false when a password (or a completed setup)
 * already exists — two racing requests can never both succeed.
 */
export async function storeInitialPassword(env: Env, hash: string): Promise<boolean> {
  const now = Date.now();
  const r = await env.DB.prepare(
    `INSERT INTO settings (key, value, updated_at)
     SELECT ?1, ?2, ?3
     WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key IN ('secret:admin_password_hash', ?1, ?4))`,
  ).bind(`secret:${LOCAL_PW_KEY}`, hash, now, `secret:${SETUP_DONE_KEY}`).run();
  if (!r.meta.changes) return false;
  await env.DB.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO NOTHING')
    .bind(`secret:${SETUP_DONE_KEY}`, String(now), now).run();
  return true;
}
