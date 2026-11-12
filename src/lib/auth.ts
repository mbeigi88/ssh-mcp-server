import type { Env } from '../env';
import { b64urlDecode, hmacHex, randomToken, sha256Hex, timingSafeEqualStr, verifyPassword } from './crypto';
import { getSecretSetting, getSettings } from './db';
import { sessionSecretProblem } from './config';

export const SESSION_COOKIE = '__Host-sshmcp_session';
export const SESSION_COOKIE_DEV = 'sshmcp_session';

export function cookieName(env: Env): string {
  return env.DEV_INSECURE_COOKIES === 'true' ? SESSION_COOKIE_DEV : SESSION_COOKIE;
}

export function sessionCookie(env: Env, token: string, maxAgeSeconds: number): string {
  const secure = env.DEV_INSECURE_COOKIES === 'true' ? '' : '; Secure';
  return `${cookieName(env)}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}${secure}`;
}
export function clearSessionCookie(env: Env): string {
  const secure = env.DEV_INSECURE_COOKIES === 'true' ? '' : '; Secure';
  return `${cookieName(env)}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}

export function readCookie(req: Request, name: string): string | null {
  const h = req.headers.get('cookie');
  if (!h) return null;
  for (const part of h.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function requireSessionSecret(env: Env): string {
  if (sessionSecretProblem(env.SESSION_SECRET)) throw new Error('SESSION_SECRET is not configured (min 32 chars)');
  return env.SESSION_SECRET;
}

/**
 * Where the admin password hash comes from, in order of precedence:
 *  1. "legacy" — D1 setting `secret:admin_password_hash`, written by the v1 "Change admin password" form.
 *     v1 let it override the secret, and only v1 ever wrote it, so it keeps overriding (no lock-out on upgrade).
 *  2. "secret" — the ADMIN_PASSWORD_HASH Worker secret.
 *  3. "d1"     — D1 setting `secret:admin_password_hash_local`, written by first-run setup or by
 *     "Change admin password" when no secret is set. Setting the secret later overrides it (recovery path).
 */
export type PasswordSource = 'legacy' | 'secret' | 'd1';
export const LEGACY_PW_KEY = 'admin_password_hash';
export const LOCAL_PW_KEY = 'admin_password_hash_local';

export async function adminPassword(env: Env): Promise<{ hash: string; source: PasswordSource } | null> {
  const legacy = await getSecretSetting(env, LEGACY_PW_KEY);
  if (legacy) return { hash: legacy, source: 'legacy' };
  if (env.ADMIN_PASSWORD_HASH && env.ADMIN_PASSWORD_HASH.trim()) return { hash: env.ADMIN_PASSWORD_HASH.trim(), source: 'secret' };
  const local = await getSecretSetting(env, LOCAL_PW_KEY);
  if (local) return { hash: local, source: 'd1' };
  return null;
}

export async function adminPasswordHash(env: Env): Promise<string | null> {
  return (await adminPassword(env))?.hash ?? null;
}

export async function checkAdminPassword(env: Env, password: string): Promise<boolean> {
  const stored = await adminPasswordHash(env);
  if (!stored) return false;
  return verifyPassword(password, stored);
}

export interface SessionInfo {
  id: string;
  csrf_token: string;
  expires_at: number;
}

export async function createSession(env: Env, req: Request): Promise<{ token: string; session: SessionInfo; maxAge: number }> {
  const settings = await getSettings(env);
  const token = randomToken(32);
  const id = await hmacHex(requireSessionSecret(env), token);
  const csrf = randomToken(24);
  const now = Date.now();
  const maxAge = settings.session_ttl_hours * 3600;
  const expires = now + maxAge * 1000;
  await env.DB.prepare('INSERT INTO sessions (id, csrf_token, created_at, expires_at, last_seen_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(id, csrf, now, expires, now, clientIp(req), (req.headers.get('user-agent') ?? '').slice(0, 200))
    .run();
  return { token, session: { id, csrf_token: csrf, expires_at: expires }, maxAge };
}

export async function getSession(env: Env, req: Request): Promise<SessionInfo | null> {
  const token = readCookie(req, cookieName(env));
  if (!token || token.length > 128) return null;
  const id = await hmacHex(requireSessionSecret(env), token);
  const row = await env.DB.prepare('SELECT id, csrf_token, expires_at FROM sessions WHERE id = ?').bind(id).first<SessionInfo>();
  if (!row) return null;
  if (row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
    return null;
  }
  // touch at most once a minute
  await env.DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ? AND last_seen_at < ?').bind(Date.now(), id, Date.now() - 60_000).run();
  return row;
}

export async function destroySession(env: Env, req: Request): Promise<void> {
  const token = readCookie(req, cookieName(env));
  if (!token) return;
  const id = await hmacHex(requireSessionSecret(env), token);
  await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
}

export function checkCsrf(req: Request, session: SessionInfo): boolean {
  const header = req.headers.get('x-csrf-token');
  if (!header) return false;
  if (!timingSafeEqualStr(header, session.csrf_token)) return false;
  // Defense in depth: when the browser sends Origin, it must match our own origin.
  const origin = req.headers.get('origin');
  if (origin && origin !== new URL(req.url).origin) return false;
  return true;
}

export function clientIp(req: Request): string {
  return req.headers.get('cf-connecting-ip') ?? req.headers.get('x-real-ip') ?? 'unknown';
}

// ---------------- MCP bearer tokens ----------------

export const MCP_TOKEN_PREFIX = 'sshmcp_';

export async function hashMcpToken(token: string): Promise<string> {
  return sha256Hex(token);
}

export async function verifyMcpBearer(env: Env, req: Request): Promise<{ id: string; name: string } | null> {
  const h = req.headers.get('authorization') ?? '';
  const m = /^Bearer\s+(\S+)$/i.exec(h);
  if (!m || !m[1].startsWith(MCP_TOKEN_PREFIX) || m[1].length > 200) return null;
  const hash = await hashMcpToken(m[1]);
  const row = await env.DB.prepare('SELECT id, name FROM mcp_tokens WHERE token_hash = ? AND revoked_at IS NULL').bind(hash).first<{ id: string; name: string }>();
  if (!row) return null;
  await env.DB.prepare('UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?').bind(Date.now(), row.id).run();
  return row;
}

// ---------------- Cloudflare Access JWT ----------------

interface Jwk { kid: string; kty: string; n: string; e: string; alg?: string }
type JwksFetcher = (url: string) => Promise<{ keys: Jwk[] }>;

let jwksCache: { url: string; at: number; keys: Jwk[] } | null = null;

const defaultJwksFetcher: JwksFetcher = async (url) => {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`JWKS fetch failed: ${r.status}`);
  return r.json();
};

/**
 * Verifies the Cf-Access-Jwt-Assertion header (RS256) against the team's JWKS,
 * checking signature, audience, issuer, exp and nbf. Returns the email/sub on success.
 */
export async function verifyAccessJwt(
  env: Pick<Env, 'ACCESS_TEAM_DOMAIN' | 'ACCESS_AUD'>,
  req: Request,
  fetcher: JwksFetcher = defaultJwksFetcher,
  nowSec = Math.floor(Date.now() / 1000),
): Promise<{ email: string } | null> {
  const token = req.headers.get('cf-access-jwt-assertion');
  if (!token || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  let header: { alg: string; kid: string };
  let payload: { aud: string | string[]; iss: string; exp: number; nbf?: number; email?: string; sub?: string };
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  } catch {
    return null;
  }
  if (header.alg !== 'RS256') return null;
  const team = env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const issuer = `https://${team}`;
  const url = `${issuer}/cdn-cgi/access/certs`;
  if (!jwksCache || jwksCache.url !== url || Date.now() - jwksCache.at > 3600_000) {
    jwksCache = { url, at: Date.now(), keys: (await fetcher(url)).keys };
  }
  const jwk = jwksCache.keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlDecode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!ok) return null;
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(env.ACCESS_AUD)) return null;
  if (payload.iss !== issuer) return null;
  if (typeof payload.exp !== 'number' || payload.exp < nowSec) return null;
  if (payload.nbf && payload.nbf > nowSec + 60) return null;
  return { email: payload.email ?? payload.sub ?? 'access-user' };
}

export function _resetJwksCacheForTests() { jwksCache = null; }
