// OAuth 2.1 authorization server for MCP clients (MCP spec 2025-06-18 "Authorization").
//
//  * RFC 9728 protected-resource metadata  -> /.well-known/oauth-protected-resource[/mcp]
//  * RFC 8414 authorization-server metadata -> /.well-known/oauth-authorization-server (+ openid-configuration alias)
//  * RFC 7591 dynamic client registration   -> POST /oauth/register
//  * Authorization code + PKCE (S256 only)  -> GET/POST /oauth/authorize, POST /oauth/token
//  * Refresh-token rotation, RFC 7009 revocation -> POST /oauth/revoke
//
// The human approves a client on /oauth/authorize with the dashboard admin password (or a valid
// Cloudflare Access identity when AUTH_MODE is "access"/"both"). Access tokens are opaque, stored
// only as SHA-256 hashes, and accepted on /mcp next to the dashboard-issued sshmcp_ tokens.
import { Hono } from 'hono';
import type { Context } from 'hono';
import type { Env } from '../env';
import { audit } from './db';
import { checkAdminPassword, adminPasswordHash, clientIp, verifyAccessJwt } from './auth';
import { rateLimit } from './ratelimit';
import { b64url, hmacHex, randomToken, sha256Hex, timingSafeEqualStr } from './crypto';

export const OAUTH_ACCESS_PREFIX = 'sshmcp_oat_';
export const OAUTH_REFRESH_PREFIX = 'sshmcp_ort_';
const ACCESS_TTL_S = 3600;
const REFRESH_TTL_S = 30 * 24 * 3600;
const CODE_TTL_S = 300;
const SCOPE = 'mcp';

type C = Context<{ Bindings: Env }>;

interface ClientRow {
  client_id: string;
  client_secret_hash: string | null;
  client_name: string;
  redirect_uris: string;
  token_endpoint_auth_method: string;
}

export function issuer(req: Request): string {
  return new URL(req.url).origin;
}
export function resourceMetadataUrl(req: Request): string {
  return `${issuer(req)}/.well-known/oauth-protected-resource`;
}

function authMode(env: Env): 'password' | 'access' | 'both' {
  const m = (env.AUTH_MODE ?? 'password').toLowerCase();
  return m === 'access' || m === 'both' ? m : 'password';
}

const CORS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version',
  'access-control-max-age': '86400',
};

function json(c: C, body: unknown, status = 200, extra: Record<string, string> = {}) {
  return c.json(body as object, status as 200, { ...CORS, 'cache-control': 'no-store', pragma: 'no-cache', ...extra });
}
function oauthError(c: C, error: string, description: string, status = 400, extra: Record<string, string> = {}) {
  return json(c, { error, error_description: description }, status, extra);
}

export function protectedResourceMetadata(req: Request) {
  const iss = issuer(req);
  return {
    resource: `${iss}/mcp`,
    authorization_servers: [iss],
    bearer_methods_supported: ['header'],
    scopes_supported: [SCOPE],
    resource_name: 'cf-ssh-mcp',
  };
}

export function authorizationServerMetadata(req: Request) {
  const iss = issuer(req);
  return {
    issuer: iss,
    authorization_endpoint: `${iss}/oauth/authorize`,
    token_endpoint: `${iss}/oauth/token`,
    registration_endpoint: `${iss}/oauth/register`,
    revocation_endpoint: `${iss}/oauth/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    scopes_supported: [SCOPE],
    authorization_response_iss_parameter_supported: true,
    service_documentation: 'https://github.com/robamad1396-dev/cf-ssh-mcp',
  };
}

/** https anywhere, http only on loopback, or a private-use app scheme (com.example.app:/cb, cursor://...). */
export function redirectUriAllowed(u: string): boolean {
  if (u.length > 2000) return false;
  let url: URL;
  try {
    url = new URL(u);
  } catch {
    return false;
  }
  if (url.hash) return false;
  const p = url.protocol;
  if (p === 'https:') return true;
  if (p === 'http:') return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (['javascript:', 'data:', 'file:', 'blob:', 'vbscript:', 'about:', 'ftp:', 'ws:', 'wss:'].includes(p)) return false;
  return /^[a-z][a-z0-9+.-]*:$/.test(p);
}

/** RFC 8252: loopback redirect URIs match regardless of port. */
function redirectMatches(registered: string[], given: string): boolean {
  if (registered.includes(given)) return true;
  let g: URL;
  try {
    g = new URL(given);
  } catch {
    return false;
  }
  if (g.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(g.hostname)) return false;
  return registered.some((r) => {
    try {
      const u = new URL(r);
      return u.protocol === 'http:' && u.hostname === g.hostname && u.pathname === g.pathname && u.search === g.search;
    } catch {
      return false;
    }
  });
}

async function getClient(env: Env, id: string | undefined | null): Promise<ClientRow | null> {
  if (!id || id.length > 100) return null;
  return env.DB.prepare('SELECT client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method FROM oauth_clients WHERE client_id = ?')
    .bind(id)
    .first<ClientRow>();
}

async function s256(verifier: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
}

async function readForm(c: C): Promise<Record<string, string>> {
  const ct = c.req.header('content-type') ?? '';
  if (ct.includes('application/json')) {
    const j = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(j).filter(([, v]) => typeof v === 'string')) as Record<string, string>;
  }
  const body = await c.req.parseBody().catch(() => ({}));
  return Object.fromEntries(Object.entries(body).filter(([, v]) => typeof v === 'string')) as Record<string, string>;
}

/** Client authentication at the token / revocation endpoints. */
async function authenticateClient(c: C, form: Record<string, string>): Promise<ClientRow | null> {
  let id = form.client_id;
  let secret = form.client_secret;
  const h = c.req.header('authorization');
  if (h && /^Basic\s+/i.test(h)) {
    try {
      const [u, p] = atob(h.replace(/^Basic\s+/i, '')).split(':');
      id = decodeURIComponent(u);
      secret = decodeURIComponent(p ?? '');
    } catch {
      return null;
    }
  }
  const client = await getClient(c.env, id);
  if (!client) return null;
  if (client.client_secret_hash) {
    if (!secret) return null;
    if (!timingSafeEqualStr(await sha256Hex(secret), client.client_secret_hash)) return null;
  }
  return client;
}

async function issueTokens(env: Env, grantId: string) {
  const access = OAUTH_ACCESS_PREFIX + randomToken(32);
  const refresh = OAUTH_REFRESH_PREFIX + randomToken(32);
  const now = Date.now();
  await env.DB.prepare(
    'UPDATE oauth_grants SET access_token_hash = ?, access_expires_at = ?, refresh_token_hash = ?, refresh_expires_at = ?, last_used_at = ? WHERE id = ?',
  )
    .bind(await sha256Hex(access), now + ACCESS_TTL_S * 1000, await sha256Hex(refresh), now + REFRESH_TTL_S * 1000, now, grantId)
    .run();
  return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL_S, refresh_token: refresh, scope: SCOPE };
}

/** Used by /mcp: returns the grant as an MCP "token" identity, or null. */
export async function verifyOAuthAccessToken(env: Env, token: string): Promise<{ id: string; name: string } | null> {
  if (!token.startsWith(OAUTH_ACCESS_PREFIX) || token.length > 200) return null;
  const row = await env.DB.prepare(
    `SELECT g.id, g.access_expires_at, c.client_name FROM oauth_grants g JOIN oauth_clients c ON c.client_id = g.client_id
     WHERE g.access_token_hash = ? AND g.revoked_at IS NULL`,
  )
    .bind(await sha256Hex(token))
    .first<{ id: string; access_expires_at: number; client_name: string }>();
  if (!row || row.access_expires_at <= Date.now()) return null;
  await env.DB.prepare('UPDATE oauth_grants SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)')
    .bind(Date.now(), row.id, Date.now() - 60_000)
    .run();
  return { id: `oauth:${row.id}`, name: `oauth:${row.client_name}`.slice(0, 120) };
}

// ------------------------------------------------------------------ consent page

interface AuthzParams {
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  scope: string;
  resource: string;
}

async function signParams(env: Env, p: AuthzParams): Promise<string> {
  const exp = Date.now() + 15 * 60_000;
  const sig = await hmacHex(env.SESSION_SECRET, `oauth-consent|${exp}|${JSON.stringify(p)}`);
  return `${exp}.${sig}`;
}
async function checkSignedParams(env: Env, p: AuthzParams, tok: string | undefined): Promise<boolean> {
  if (!tok) return false;
  const [expS, sig] = tok.split('.');
  const exp = Number(expS);
  if (!Number.isFinite(exp) || exp < Date.now() || !sig) return false;
  const want = await hmacHex(env.SESSION_SECRET, `oauth-consent|${exp}|${JSON.stringify(p)}`);
  return timingSafeEqualStr(want, sig);
}

function consentPage(nonce: string, opts: { clientName: string; redirectHost: string; params: AuthzParams; sig: string; needPassword: boolean; error?: string }) {
  const hidden = Object.entries({ ...opts.params, consent_sig: opts.sig })
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v)}">`)
    .join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize ${escapeHtml(opts.clientName)} · cf-ssh-mcp</title>
<style nonce="${nonce}">
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1115;color:#e6e8ee;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:16px}
.card{background:#171a21;border:1px solid #2a2f3a;border-radius:14px;padding:28px;max-width:420px;width:100%;box-shadow:0 10px 30px rgba(0,0,0,.35)}
h1{font-size:20px;margin:0 0 8px}p{margin:8px 0;color:#b5bac6}.c{color:#fff;font-weight:600}
.warn{background:#3a2a12;border:1px solid #7a5a1c;color:#f3d39b;border-radius:8px;padding:10px 12px;font-size:13px;margin:14px 0}
.err{background:#3a1515;border:1px solid #7a2a2a;color:#f5b4b4;border-radius:8px;padding:10px 12px;font-size:13px;margin:12px 0}
label{display:block;margin:14px 0 6px;font-size:13px;color:#b5bac6}input[type=password]{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #2f3542;background:#0f1115;color:#fff;font-size:15px}
.row{display:flex;gap:10px;margin-top:18px}button{flex:1;padding:11px;border-radius:8px;border:0;font-size:15px;cursor:pointer}
.ok{background:#3b82f6;color:#fff}.no{background:#2a2f3a;color:#e6e8ee}</style></head><body>
<form class="card" method="post" action="/oauth/authorize">
<h1>Authorize MCP access</h1>
<p><span class="c">${escapeHtml(opts.clientName)}</span> wants to use this SSH MCP server.</p>
<p>After approval it will be redirected to <span class="c">${escapeHtml(opts.redirectHost)}</span>.</p>
<div class="warn">It will be able to run commands on your servers, within the same policy and approval rules as your other MCP tokens.</div>
${opts.error ? `<div class="err">${escapeHtml(opts.error)}</div>` : ''}
${hidden}
${opts.needPassword ? '<label for="pw">Dashboard admin password</label><input id="pw" type="password" name="password" autocomplete="current-password" required autofocus>' : ''}
<div class="row"><button class="no" type="submit" name="decision" value="deny" formnovalidate>Deny</button><button class="ok" type="submit" name="decision" value="approve">Approve</button></div>
</form></body></html>`;
}

function errorPage(nonce: string, msg: string) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorization error</title>
<style nonce="${nonce}">body{font:15px system-ui,sans-serif;background:#0f1115;color:#e6e8ee;padding:40px;text-align:center}</style></head>
<body><h1>Authorization error</h1><p>${escapeHtml(msg)}</p></body></html>`;
}

function redirectWith(uri: string, params: Record<string, string | undefined>): string {
  const u = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') u.searchParams.set(k, v);
  return u.toString();
}

/** Lets the CSP allow the consent form to redirect to the client's callback. */
function setFormAction(c: C, redirectUri: string) {
  try {
    const u = new URL(redirectUri);
    const src = u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : u.protocol;
    c.set('cspFormAction' as never, src as never);
  } catch {
    /* ignore */
  }
}

async function accessIdentity(c: C): Promise<string | null> {
  const mode = authMode(c.env);
  if (mode === 'password') return null;
  const r = await verifyAccessJwt(c.env, c.req.raw).catch(() => null);
  return r?.email ?? null;
}

// ------------------------------------------------------------------ routes

export const oauth = new Hono<{ Bindings: Env }>();

oauth.options('*', () => new Response(null, { status: 204, headers: CORS }));

oauth.get('/.well-known/oauth-protected-resource', (c) => json(c, protectedResourceMetadata(c.req.raw)));
oauth.get('/.well-known/oauth-protected-resource/mcp', (c) => json(c, protectedResourceMetadata(c.req.raw)));
oauth.get('/.well-known/oauth-authorization-server', (c) => json(c, authorizationServerMetadata(c.req.raw)));
oauth.get('/.well-known/oauth-authorization-server/mcp', (c) => json(c, authorizationServerMetadata(c.req.raw)));
oauth.get('/.well-known/openid-configuration', (c) => json(c, authorizationServerMetadata(c.req.raw)));
oauth.get('/.well-known/openid-configuration/mcp', (c) => json(c, authorizationServerMetadata(c.req.raw)));
oauth.get('/mcp/.well-known/openid-configuration', (c) => json(c, authorizationServerMetadata(c.req.raw)));

// RFC 7591 dynamic client registration (open, rate limited; a client is useless without the admin's approval).
oauth.post('/oauth/register', async (c) => {
  const ip = clientIp(c.req.raw);
  const rl = await rateLimit(c.env, `oauthreg:${ip}`, 20, 3600);
  if (!rl.ok) return oauthError(c, 'too_many_requests', 'registration rate limit exceeded', 429);
  const meta = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!meta || typeof meta !== 'object') return oauthError(c, 'invalid_client_metadata', 'body must be a JSON object');
  const uris = meta.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every((u) => typeof u === 'string' && redirectUriAllowed(u))) {
    return oauthError(c, 'invalid_redirect_uri', 'redirect_uris must be 1-10 https, loopback http, or private-scheme URIs without fragments');
  }
  const method = typeof meta.token_endpoint_auth_method === 'string' ? meta.token_endpoint_auth_method : 'none';
  if (!['none', 'client_secret_post', 'client_secret_basic'].includes(method)) {
    return oauthError(c, 'invalid_client_metadata', 'unsupported token_endpoint_auth_method');
  }
  const grantTypes = Array.isArray(meta.grant_types) ? (meta.grant_types as unknown[]) : ['authorization_code', 'refresh_token'];
  if (!grantTypes.every((g) => g === 'authorization_code' || g === 'refresh_token')) {
    return oauthError(c, 'invalid_client_metadata', 'unsupported grant_types');
  }
  const name = (typeof meta.client_name === 'string' && meta.client_name.trim() ? meta.client_name.trim() : 'MCP client').slice(0, 80);
  const clientId = 'mcpc_' + randomToken(18);
  const secret = method === 'none' ? null : 'mcps_' + randomToken(32);
  const now = Date.now();
  await c.env.DB.prepare(
    'INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  )
    .bind(clientId, secret ? await sha256Hex(secret) : null, name, JSON.stringify(uris), method, now)
    .run();
  await audit(c.env, { actor: 'anonymous', action: 'oauth.register', detail: { client_id: clientId, client_name: name }, ip });
  return json(
    c,
    {
      client_id: clientId,
      client_id_issued_at: Math.floor(now / 1000),
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
      client_name: name,
      redirect_uris: uris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: method,
      scope: SCOPE,
    },
    201,
  );
});

async function parseAuthz(c: C, src: Record<string, string | undefined>) {
  const client = await getClient(c.env, src.client_id);
  if (!client) return { fatal: 'Unknown client_id. Remove the server from your MCP client and add it again so it can re-register.' } as const;
  const registered: string[] = JSON.parse(client.redirect_uris);
  let redirect = src.redirect_uri ?? '';
  if (!redirect && registered.length === 1) redirect = registered[0];
  if (!redirect || !redirectMatches(registered, redirect)) return { fatal: 'redirect_uri does not match the registered client.' } as const;
  const params: AuthzParams = {
    client_id: client.client_id,
    redirect_uri: redirect,
    state: (src.state ?? '').slice(0, 1000),
    code_challenge: src.code_challenge ?? '',
    scope: SCOPE,
    resource: (src.resource ?? '').slice(0, 500),
  };
  return { client, params } as const;
}

oauth.get('/oauth/authorize', async (c) => {
  const nonce = randomToken(16);
  c.set('cspNonce' as never, nonce as never);
  const q = c.req.query();
  const p = await parseAuthz(c, q);
  if ('fatal' in p) return c.html(errorPage(nonce, p.fatal!), 400);
  const { client, params } = p;
  const fail = (error: string, desc: string) =>
    c.redirect(redirectWith(params.redirect_uri, { error, error_description: desc, state: params.state, iss: issuer(c.req.raw) }), 302);
  if (q.response_type !== 'code') return fail('unsupported_response_type', 'only response_type=code is supported');
  if (!params.code_challenge || (q.code_challenge_method ?? 'plain') !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(params.code_challenge)) {
    return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required');
  }
  if (q.scope && !q.scope.split(/\s+/).every((s) => s === SCOPE || s === '' || s === 'openid' || s === 'offline_access')) {
    return fail('invalid_scope', `only the "${SCOPE}" scope is supported`);
  }
  const mode = authMode(c.env);
  const viaAccess = await accessIdentity(c);
  if (!viaAccess && mode !== 'access' && !(await adminPasswordHash(c.env))) {
    return c.html(errorPage(nonce, 'The admin password is not configured yet. Open the dashboard and finish first-time setup.'), 503);
  }
  if (!viaAccess && mode === 'access') return c.html(errorPage(nonce, 'Sign in through Cloudflare Access first.'), 401);
  setFormAction(c, params.redirect_uri);
  const host = (() => {
    try {
      return new URL(params.redirect_uri).host || params.redirect_uri;
    } catch {
      return params.redirect_uri;
    }
  })();
  return c.html(consentPage(nonce, { clientName: client.client_name, redirectHost: host, params, sig: await signParams(c.env, params), needPassword: !viaAccess }));
});

oauth.post('/oauth/authorize', async (c) => {
  const nonce = randomToken(16);
  c.set('cspNonce' as never, nonce as never);
  const ip = clientIp(c.req.raw);
  const origin = c.req.header('origin');
  if (origin && origin !== 'null' && origin !== issuer(c.req.raw)) return c.html(errorPage(nonce, 'Cross-site request rejected.'), 403);
  const f = await readForm(c);
  const p = await parseAuthz(c, f);
  if ('fatal' in p) return c.html(errorPage(nonce, p.fatal!), 400);
  const { client, params } = p;
  params.code_challenge = f.code_challenge ?? '';
  if (!(await checkSignedParams(c.env, params, f.consent_sig))) {
    return c.html(errorPage(nonce, 'This authorization request expired or was tampered with. Start the connection again from your MCP client.'), 400);
  }
  const iss = issuer(c.req.raw);
  setFormAction(c, params.redirect_uri);
  if (f.decision !== 'approve') {
    await audit(c.env, { actor: 'admin', action: 'oauth.deny', detail: { client_id: client.client_id, client_name: client.client_name }, ip });
    return c.redirect(redirectWith(params.redirect_uri, { error: 'access_denied', error_description: 'the user denied the request', state: params.state, iss }), 302);
  }
  const viaAccess = await accessIdentity(c);
  if (!viaAccess) {
    const rl1 = await rateLimit(c.env, `login:${ip}:m`, 5, 60);
    const rl2 = await rateLimit(c.env, `login:${ip}:h`, 30, 3600);
    const again = async (msg: string, status: number) =>
      c.html(
        consentPage(nonce, { clientName: client.client_name, redirectHost: new URL(params.redirect_uri).host || params.redirect_uri, params, sig: await signParams(c.env, params), needPassword: true, error: msg }),
        status as 401,
      );
    if (!rl1.ok || !rl2.ok) {
      await audit(c.env, { actor: 'anonymous', action: 'oauth.authorize', outcome: 'rate_limited', ip });
      return again('Too many attempts. Wait a minute and try again.', 429);
    }
    if (authMode(c.env) === 'access' || !(await checkAdminPassword(c.env, f.password ?? ''))) {
      await audit(c.env, { actor: 'anonymous', action: 'oauth.authorize', outcome: 'denied', detail: { client_id: client.client_id }, ip });
      return again('Wrong password.', 401);
    }
  }
  const grantId = 'grant_' + randomToken(12);
  const code = randomToken(32);
  const now = Date.now();
  await c.env.DB.batch([
    c.env.DB.prepare('INSERT INTO oauth_grants (id, client_id, scope, resource, created_at) VALUES (?, ?, ?, ?, ?)').bind(grantId, client.client_id, SCOPE, params.resource || null, now),
    c.env.DB.prepare('INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, resource, grant_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(
      await sha256Hex(code),
      client.client_id,
      params.redirect_uri,
      params.code_challenge,
      SCOPE,
      params.resource || null,
      grantId,
      now + CODE_TTL_S * 1000,
    ),
    c.env.DB.prepare('DELETE FROM oauth_codes WHERE expires_at < ?').bind(now),
  ]);
  await audit(c.env, { actor: viaAccess ? `access:${viaAccess}` : 'admin', action: 'oauth.approve', detail: { client_id: client.client_id, client_name: client.client_name, grant: grantId }, ip });
  return c.redirect(redirectWith(params.redirect_uri, { code, state: params.state, iss }), 302);
});

oauth.post('/oauth/token', async (c) => {
  const ip = clientIp(c.req.raw);
  const rl = await rateLimit(c.env, `oauthtok:${ip}`, 60, 60);
  if (!rl.ok) return oauthError(c, 'slow_down', 'too many token requests', 429);
  const f = await readForm(c);
  const client = await authenticateClient(c, f);
  if (!client) return oauthError(c, 'invalid_client', 'client authentication failed', 401, { 'www-authenticate': 'Basic realm="cf-ssh-mcp"' });

  if (f.grant_type === 'authorization_code') {
    if (!f.code || !f.code_verifier) return oauthError(c, 'invalid_request', 'code and code_verifier are required');
    const row = await c.env.DB.prepare('DELETE FROM oauth_codes WHERE code_hash = ? RETURNING client_id, redirect_uri, code_challenge, grant_id, expires_at')
      .bind(await sha256Hex(f.code))
      .first<{ client_id: string; redirect_uri: string; code_challenge: string; grant_id: string; expires_at: number }>();
    if (!row || row.expires_at < Date.now() || row.client_id !== client.client_id) return oauthError(c, 'invalid_grant', 'authorization code is invalid or expired');
    if (f.redirect_uri && f.redirect_uri !== row.redirect_uri) return oauthError(c, 'invalid_grant', 'redirect_uri mismatch');
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(f.code_verifier) || !timingSafeEqualStr(await s256(f.code_verifier), row.code_challenge)) {
      await c.env.DB.prepare('UPDATE oauth_grants SET revoked_at = ? WHERE id = ?').bind(Date.now(), row.grant_id).run();
      return oauthError(c, 'invalid_grant', 'PKCE verification failed');
    }
    await c.env.DB.prepare('UPDATE oauth_clients SET last_used_at = ? WHERE client_id = ?').bind(Date.now(), client.client_id).run();
    return json(c, await issueTokens(c.env, row.grant_id));
  }

  if (f.grant_type === 'refresh_token') {
    if (!f.refresh_token || !f.refresh_token.startsWith(OAUTH_REFRESH_PREFIX)) return oauthError(c, 'invalid_grant', 'refresh_token is invalid');
    const g = await c.env.DB.prepare('SELECT id, client_id, refresh_expires_at, revoked_at FROM oauth_grants WHERE refresh_token_hash = ?')
      .bind(await sha256Hex(f.refresh_token))
      .first<{ id: string; client_id: string; refresh_expires_at: number; revoked_at: number | null }>();
    if (!g || g.revoked_at || g.refresh_expires_at < Date.now() || g.client_id !== client.client_id) return oauthError(c, 'invalid_grant', 'refresh_token is invalid or expired');
    return json(c, await issueTokens(c.env, g.id));
  }

  return oauthError(c, 'unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
});

// RFC 7009: always 200, even for unknown tokens.
oauth.post('/oauth/revoke', async (c) => {
  const f = await readForm(c);
  const client = await authenticateClient(c, f);
  if (!client) return oauthError(c, 'invalid_client', 'client authentication failed', 401);
  if (f.token) {
    const h = await sha256Hex(f.token);
    await c.env.DB.prepare('UPDATE oauth_grants SET revoked_at = ? WHERE client_id = ? AND (access_token_hash = ? OR refresh_token_hash = ?)')
      .bind(Date.now(), client.client_id, h, h)
      .run();
  }
  return json(c, {});
});
