import { Hono, type Context } from 'hono';
import { z } from 'zod';
import type { Env } from '../env';
import {
  audit, decryptCredentials, encryptCredentials, getServer, getSettings, listServers, putSecretSetting, putSettings, randomId, toPublic, UserError,
  type Credentials, type ServerRow,
} from '../lib/db';
import {
  checkAdminPassword, checkCsrf, clearSessionCookie, clientIp, createSession, destroySession, getSession, hashMcpToken, MCP_TOKEN_PREFIX,
  sessionCookie, verifyAccessJwt, adminPassword, adminPasswordHash, readCookie, LOCAL_PW_KEY, LEGACY_PW_KEY, type SessionInfo,
} from '../lib/auth';
import { configIssues, describeIssues } from '../lib/config';
import { passwordProblem, setupState, setupTokenMatches, storeInitialPassword } from '../lib/setup';
import { hashPassword, randomToken, sha256Hex, timingSafeEqualStr } from '../lib/crypto';
import { rateLimit } from '../lib/ratelimit';
import { approveAllSchema, autoApproveSchema, changePasswordSchema, execSchema, formatZodError, loginSchema, setupSchema, pathSchema, serverCreateSchema, serverUpdateSchema, settingsSchema } from '../lib/validation';
import { checkFileOp, deleteFile, policyOf, runCommand, sshStub } from '../services/ops';
import { decide } from '../lib/policy';
import { autoApproveCommand, isAllConfirmText, normalizeLevel, type AutoApproveLevel } from '../lib/auto-approve';

const ALL_CONFIRM_ERROR = 'enabling auto-approve level "all" requires typing the confirmation word (CONFIRM / تأیید)';
function requireAllConfirm(level: AutoApproveLevel | undefined, prev: AutoApproveLevel | undefined, text: string | undefined) {
  if (level === 'all' && prev !== 'all' && !isAllConfirmText(text)) throw new UserError(ALL_CONFIRM_ERROR);
}
import { validateRemotePath } from '../lib/quote';
import { checkPrivateKey } from '../ssh/client';

type Vars = { session: SessionInfo; actor: string };
type C = Context<{ Bindings: Env; Variables: Vars }>;

export const api = new Hono<{ Bindings: Env; Variables: Vars }>();

const MAX_JSON = 2 * 1024 * 1024;
const MAX_UPLOAD_CHUNK = 8 * 1024 * 1024;

async function body<T extends z.ZodTypeAny>(c: C, schema: T): Promise<z.infer<T>> {
  const len = Number(c.req.header('content-length') ?? '0');
  if (len > MAX_JSON) throw new UserError('request body too large', 413);
  let raw: unknown;
  try {
    const text = await c.req.text();
    if (text.length > MAX_JSON) throw new UserError('request body too large', 413);
    raw = text ? JSON.parse(text) : {};
  } catch (e) {
    if (e instanceof UserError) throw e;
    throw new UserError('invalid JSON body');
  }
  const r = schema.safeParse(raw);
  if (!r.success) throw new UserError(formatZodError(r.error));
  return r.data;
}

function authMode(env: Env): 'password' | 'access' | 'both' {
  const m = (env.AUTH_MODE ?? 'password').toLowerCase();
  return m === 'access' || m === 'both' ? m : 'password';
}

// ---------------------------------------------------------------- configuration check

// Missing / short / weak ENCRYPTION_KEY or SESSION_SECRET: every API call except /auth/me (which tells the
// dashboard what is wrong so it can show an explanation page) answers 503 instead of crashing.
api.use('*', async (c, next) => {
  const p = new URL(c.req.url).pathname;
  if (p === '/api/auth/me') return next();
  const issues = configIssues(c.env);
  if (issues.length) return c.json({ error: `server is not configured: ${describeIssues(issues)}`, config_errors: issues }, 503);
  return next();
});

// ---------------------------------------------------------------- public auth endpoints

api.get('/auth/me', async (c) => {
  const mode = authMode(c.env);
  const issues = configIssues(c.env);
  if (issues.length) return c.json({ authenticated: false, csrf: null, expires_at: null, auth_mode: mode, configured: false, setup: null, config_errors: issues });
  const s = await getSession(c.env, c.req.raw);
  const configured = mode === 'access' ? !!(c.env.ACCESS_AUD && c.env.ACCESS_TEAM_DOMAIN) : !!(await adminPasswordHash(c.env));
  const setup = await setupState(c.env, mode);
  return c.json({ authenticated: !!s, csrf: s?.csrf_token ?? null, expires_at: s?.expires_at ?? null, auth_mode: mode, configured, setup: setup.state, setup_reason: setup.reason ?? null, config_errors: [] });
});

// ---------------------------------------------------------------- first-run setup

function setupCookieName(env: Env) { return env.DEV_INSECURE_COOKIES === 'true' ? 'sshmcp_setup' : '__Host-sshmcp_setup'; }
function setupCookie(env: Env, value: string, maxAge: number) {
  const secure = env.DEV_INSECURE_COOKIES === 'true' ? '' : '; Secure';
  return `${setupCookieName(env)}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

/** Setup status + a CSRF token (double-submit: HttpOnly SameSite=Strict cookie + header). */
api.get('/setup', async (c) => {
  const st = await setupState(c.env, authMode(c.env));
  if (st.state !== 'available') return c.json({ state: st.state, reason: st.reason ?? null, csrf: null });
  const csrf = randomToken(24);
  c.header('set-cookie', setupCookie(c.env, csrf, 3600));
  return c.json({ state: st.state, reason: null, csrf });
});

api.post('/setup', async (c) => {
  const ip = clientIp(c.req.raw);
  const mode = authMode(c.env);
  const st = await setupState(c.env, mode);
  if (st.state !== 'available') {
    await audit(c.env, { actor: 'anonymous', action: 'auth.setup', outcome: 'denied', detail: { reason: `setup ${st.state}` }, ip });
    return c.json({ error: 'setup is disabled', state: st.state }, 403);
  }
  const rl1 = await rateLimit(c.env, `setup:${ip}:m`, 5, 60);
  const rl2 = await rateLimit(c.env, `setup:${ip}:h`, 20, 3600);
  const rl3 = await rateLimit(c.env, 'setup:global:10m', 60, 600);
  if (!rl1.ok || !rl2.ok || !rl3.ok) {
    await audit(c.env, { actor: 'anonymous', action: 'auth.setup', outcome: 'rate_limited', ip });
    return c.json({ error: 'too many attempts; try again later' }, 429, { 'retry-after': String(Math.max(rl1.ok ? 60 : rl1.retryAfter, 1)) });
  }
  // CSRF: header must equal the HttpOnly setup cookie; a browser-sent Origin must be our own.
  const header = c.req.header('x-csrf-token') ?? '';
  const cookie = readCookie(c.req.raw, setupCookieName(c.env)) ?? '';
  const origin = c.req.header('origin');
  if (!header || !cookie || !timingSafeEqualStr(header, cookie) || (origin && origin !== new URL(c.req.url).origin)) {
    await audit(c.env, { actor: 'anonymous', action: 'csrf.reject', outcome: 'denied', detail: { path: '/api/setup' }, ip });
    return c.json({ error: 'CSRF token missing or invalid — reload the page' }, 403);
  }
  const b = await body(c, setupSchema);
  if (!(await setupTokenMatches(c.env, b.setup_token))) {
    await audit(c.env, { actor: 'anonymous', action: 'auth.setup', outcome: 'denied', detail: { reason: 'wrong setup token' }, ip });
    return c.json({ error: 'wrong setup token' }, 401);
  }
  const weak = passwordProblem(b.password, c.env);
  if (weak) return c.json({ error: weak }, 400);
  if (!(await storeInitialPassword(c.env, await hashPassword(b.password)))) {
    return c.json({ error: 'setup is disabled', state: 'done' }, 403);
  }
  await audit(c.env, { actor: 'admin', action: 'auth.setup', ip });
  const { token, session, maxAge } = await createSession(c.env, c.req.raw);
  c.header('set-cookie', sessionCookie(c.env, token, maxAge));
  c.header('set-cookie', setupCookie(c.env, '', 0), { append: true });
  return c.json({ ok: true, csrf: session.csrf_token, expires_at: session.expires_at });
});

api.post('/auth/login', async (c) => {
  const ip = clientIp(c.req.raw);
  const rl1 = await rateLimit(c.env, `login:${ip}:m`, 5, 60);
  const rl2 = await rateLimit(c.env, `login:${ip}:h`, 30, 3600);
  if (!rl1.ok || !rl2.ok) {
    await audit(c.env, { actor: 'anonymous', action: 'auth.login', outcome: 'rate_limited', ip });
    return c.json({ error: 'too many login attempts; try again later' }, 429, { 'retry-after': String(Math.max(rl1.retryAfter, 1)) });
  }
  const mode = authMode(c.env);
  let actor = 'admin';
  if (mode === 'access' || mode === 'both') {
    const who = await verifyAccessJwt(c.env, c.req.raw);
    if (!who) {
      await audit(c.env, { actor: 'anonymous', action: 'auth.login', outcome: 'denied', detail: { reason: 'access jwt' }, ip });
      return c.json({ error: 'Cloudflare Access authentication required' }, 401);
    }
    actor = `access:${who.email}`;
  }
  if (mode === 'password' || mode === 'both') {
    const { password } = await body(c, loginSchema);
    if (!(await adminPasswordHash(c.env))) return c.json({ error: 'admin password is not configured yet (open the dashboard to run first-time setup, or set the ADMIN_PASSWORD_HASH secret)' }, 503);
    if (!(await checkAdminPassword(c.env, password))) {
      await audit(c.env, { actor: 'anonymous', action: 'auth.login', outcome: 'denied', ip });
      return c.json({ error: 'invalid password' }, 401);
    }
  }
  const { token, session, maxAge } = await createSession(c.env, c.req.raw);
  await audit(c.env, { actor, action: 'auth.login', ip });
  c.header('set-cookie', sessionCookie(c.env, token, maxAge));
  return c.json({ ok: true, csrf: session.csrf_token, expires_at: session.expires_at });
});

// ---------------------------------------------------------------- auth middleware

api.use('*', async (c, next) => {
  const p = new URL(c.req.url).pathname;
  if (p === '/api/auth/me' || p === '/api/auth/login' || p === '/api/setup') return next();
  const s = await getSession(c.env, c.req.raw);
  if (!s) return c.json({ error: 'authentication required' }, 401);
  const mode = authMode(c.env);
  let actor = 'admin';
  if (mode !== 'password') {
    const who = await verifyAccessJwt(c.env, c.req.raw);
    if (!who) return c.json({ error: 'Cloudflare Access authentication required' }, 401);
    actor = `access:${who.email}`;
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(c.req.method) && !checkCsrf(c.req.raw, s)) {
    await audit(c.env, { actor, action: 'csrf.reject', outcome: 'denied', detail: { path: p }, ip: clientIp(c.req.raw) });
    return c.json({ error: 'CSRF token missing or invalid' }, 403);
  }
  const rl = await rateLimit(c.env, `api:${s.id.slice(0, 16)}`, 600, 60);
  if (!rl.ok) return c.json({ error: 'rate limit exceeded' }, 429);
  c.set('session', s);
  c.set('actor', actor);
  return next();
});

api.post('/auth/logout', async (c) => {
  await destroySession(c.env, c.req.raw);
  c.header('set-cookie', clearSessionCookie(c.env));
  return c.json({ ok: true });
});

api.post('/auth/change-password', async (c) => {
  const b = await body(c, changePasswordSchema);
  const pw = await adminPassword(c.env);
  if (pw?.source === 'secret') {
    return c.json({ error: 'the admin password is set by the ADMIN_PASSWORD_HASH secret; change it with `npm run hash-password` + `wrangler secret put ADMIN_PASSWORD_HASH`, or delete that secret to manage the password here', source: 'secret' }, 409);
  }
  if (!(await checkAdminPassword(c.env, b.current_password))) return c.json({ error: 'current password is wrong' }, 403);
  const weak = passwordProblem(b.new_password, c.env);
  if (weak) return c.json({ error: weak }, 400);
  await putSecretSetting(c.env, pw?.source === 'legacy' ? LEGACY_PW_KEY : LOCAL_PW_KEY, await hashPassword(b.new_password));
  await c.env.DB.prepare('DELETE FROM sessions WHERE id != ?').bind(c.get('session').id).run();
  await audit(c.env, { actor: c.get('actor'), action: 'auth.change_password' });
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- overview

api.get('/overview', async (c) => {
  const servers = (await listServers(c.env)).map(toPublic);
  const recent = await c.env.DB.prepare('SELECT ts, actor, action, server_id, outcome, detail, auto_approved, auto_level FROM audit_log ORDER BY ts DESC LIMIT 25').all();
  const pending = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM pending_confirmations WHERE status = 'pending' AND expires_at > ?").bind(Date.now()).first<{ n: number }>();
  const cmds = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM command_results WHERE started_at > ?').bind(Date.now() - 86400_000).first<{ n: number }>();
  return c.json({
    totals: {
      servers: servers.length,
      connected: servers.filter((s) => s.status === 'connected').length,
      failed: servers.filter((s) => ['error', 'hostkey_mismatch'].includes(s.status)).length,
      pending_hostkeys: servers.filter((s) => s.status === 'hostkey_pending').length,
      pending_confirmations: pending?.n ?? 0,
      commands_24h: cmds?.n ?? 0,
    },
    servers,
    recent_activity: recent.results,
  });
});

// ---------------------------------------------------------------- servers CRUD

async function loadServer(c: C): Promise<ServerRow> {
  const row = await getServer(c.env, c.req.param('id')!);
  if (!row) throw new UserError('server not found', 404);
  return row;
}

api.get('/servers', async (c) => c.json((await listServers(c.env)).map(toPublic)));
api.get('/servers/:id', async (c) => c.json(toPublic(await loadServer(c))));

api.post('/servers', async (c) => {
  const b = await body(c, serverCreateSchema);
  if (b.auth_method === 'key' && b.private_key) {
    try { checkPrivateKey(b.private_key, b.passphrase || undefined); } catch (e) { throw new UserError((e as Error).message); }
  }
  requireAllConfirm(b.auto_approve, undefined, b.auto_approve_confirm);
  const autoLevel: AutoApproveLevel = b.auto_approve ?? (await getSettings(c.env)).default_auto_approve;
  const id = randomId('srv_');
  const now = Date.now();
  const creds: Credentials = b.auth_method === 'password' ? { password: b.password } : { privateKey: b.private_key, passphrase: b.passphrase || undefined };
  const blob = await encryptCredentials(c.env, id, creds);
  const stmts = [];
  if (b.is_default) stmts.push(c.env.DB.prepare('UPDATE servers SET is_default = 0'));
  stmts.push(
    c.env.DB.prepare(
      `INSERT INTO servers (id, name, host, port, username, auth_method, cred_ciphertext, cred_iv, cred_key_version, has_password, has_private_key, has_passphrase,
        host_key_fingerprint, labels, is_default, allow_root, policy_mode, allow_sudo_install, auto_approve, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'disconnected', ?, ?)`,
    ).bind(
      id, b.name, b.host, b.port, b.username, b.auth_method, blob.ciphertext, blob.iv, blob.keyVersion,
      creds.password ? 1 : 0, creds.privateKey ? 1 : 0, creds.passphrase ? 1 : 0,
      b.host_key_fingerprint || null, JSON.stringify(b.labels), b.is_default ? 1 : 0, b.allow_root ? 1 : 0, b.policy_mode, b.allow_sudo_install ? 1 : 0, autoLevel, now, now,
    ),
  );
  try {
    await c.env.DB.batch(stmts);
  } catch (e) {
    if (/UNIQUE/i.test((e as Error).message)) throw new UserError('a server with this name already exists', 409);
    throw e;
  }
  const count = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM servers').first<{ n: number }>();
  if (count?.n === 1) await c.env.DB.prepare('UPDATE servers SET is_default = 1 WHERE id = ?').bind(id).run();
  await audit(c.env, { actor: c.get('actor'), action: 'server.create', server_id: id, detail: { name: b.name, host: b.host, port: b.port, username: b.username, auth_method: b.auth_method, auto_approve: autoLevel } });
  return c.json(toPublic((await getServer(c.env, id))!), 201);
});

api.patch('/servers/:id', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, serverUpdateSchema);
  const next = { ...row };
  const changed: string[] = [];
  const set = <K extends keyof ServerRow>(k: K, v: ServerRow[K]) => { if (next[k] !== v) { next[k] = v; changed.push(String(k)); } };
  if (b.name !== undefined) set('name', b.name);
  if (b.host !== undefined) set('host', b.host);
  if (b.port !== undefined) set('port', b.port);
  if (b.username !== undefined) set('username', b.username);
  if (b.auth_method !== undefined) set('auth_method', b.auth_method);
  if (b.labels !== undefined) set('labels', JSON.stringify(b.labels));
  if (b.allow_root !== undefined) set('allow_root', b.allow_root ? 1 : 0);
  if (b.policy_mode !== undefined) set('policy_mode', b.policy_mode);
  if (b.allow_sudo_install !== undefined) set('allow_sudo_install', b.allow_sudo_install ? 1 : 0);
  if (b.auto_approve !== undefined) {
    requireAllConfirm(b.auto_approve, normalizeLevel(row.auto_approve), b.auto_approve_confirm);
    set('auto_approve', b.auto_approve);
  }
  if (next.username === 'root' && !next.allow_root) throw new UserError('root login must be explicitly allowed for this server');

  // credentials: empty / omitted => unchanged
  const creds = await decryptCredentials(c.env, row);
  let credsChanged = false;
  if (b.password) { creds.password = b.password; credsChanged = true; }
  if (b.private_key) { creds.privateKey = b.private_key; credsChanged = true; }
  if (b.passphrase) { creds.passphrase = b.passphrase; credsChanged = true; }
  if (b.clear_passphrase) { delete creds.passphrase; credsChanged = true; }
  if (next.auth_method === 'password' && !creds.password) throw new UserError('a password is required for password authentication');
  if (next.auth_method === 'key') {
    if (!creds.privateKey) throw new UserError('a private key is required for key authentication');
    try { checkPrivateKey(creds.privateKey, creds.passphrase); } catch (e) { throw new UserError((e as Error).message); }
  }
  if (credsChanged) {
    const blob = await encryptCredentials(c.env, row.id, creds);
    next.cred_ciphertext = blob.ciphertext; next.cred_iv = blob.iv; next.cred_key_version = blob.keyVersion;
    next.has_password = creds.password ? 1 : 0; next.has_private_key = creds.privateKey ? 1 : 0; next.has_passphrase = creds.passphrase ? 1 : 0;
    changed.push('credentials');
  }
  // host identity changes invalidate the trusted host key
  if (b.reset_host_key || next.host !== row.host || next.port !== row.port) {
    next.host_key_fingerprint = null; next.host_key_algo = null; next.pending_fingerprint = null; next.pending_fingerprint_algo = null;
    changed.push('host_key_reset');
  }
  if (b.host_key_fingerprint) { next.host_key_fingerprint = b.host_key_fingerprint; next.pending_fingerprint = null; changed.push('host_key_fingerprint'); }
  const stmts = [];
  if (b.is_default === true) { stmts.push(c.env.DB.prepare('UPDATE servers SET is_default = 0')); next.is_default = 1; changed.push('is_default'); }
  if (b.is_default === false) next.is_default = 0;
  stmts.push(
    c.env.DB.prepare(
      `UPDATE servers SET name=?, host=?, port=?, username=?, auth_method=?, cred_ciphertext=?, cred_iv=?, cred_key_version=?, has_password=?, has_private_key=?, has_passphrase=?,
        host_key_fingerprint=?, host_key_algo=?, pending_fingerprint=?, pending_fingerprint_algo=?, labels=?, is_default=?, allow_root=?, policy_mode=?, allow_sudo_install=?, auto_approve=?, updated_at=? WHERE id=?`,
    ).bind(next.name, next.host, next.port, next.username, next.auth_method, next.cred_ciphertext, next.cred_iv, next.cred_key_version, next.has_password, next.has_private_key, next.has_passphrase,
      next.host_key_fingerprint, next.host_key_algo, next.pending_fingerprint, next.pending_fingerprint_algo, next.labels, next.is_default, next.allow_root, next.policy_mode, next.allow_sudo_install, next.auto_approve, Date.now(), row.id),
  );
  try { await c.env.DB.batch(stmts); } catch (e) {
    if (/UNIQUE/i.test((e as Error).message)) throw new UserError('a server with this name already exists', 409);
    throw e;
  }
  // drop any live session so new settings/credentials take effect (not needed for policy-only flags)
  if (changed.some((k) => !['auto_approve', 'labels', 'is_default'].includes(k))) await sshStub(c.env, row.id).disconnect('server settings changed');
  await audit(c.env, { actor: c.get('actor'), action: 'server.update', server_id: row.id, detail: { changed, ...(changed.includes('auto_approve') ? { auto_approve: { from: row.auto_approve, to: next.auto_approve } } : {}) } });
  return c.json(toPublic((await getServer(c.env, row.id))!));
});

api.delete('/servers/:id', async (c) => {
  const row = await loadServer(c);
  await sshStub(c.env, row.id).disconnect('server deleted');
  await c.env.DB.batch([
    c.env.DB.prepare('DELETE FROM servers WHERE id = ?').bind(row.id),
    c.env.DB.prepare("UPDATE pending_confirmations SET status = 'rejected' WHERE server_id = ? AND status = 'pending'").bind(row.id),
  ]);
  if (row.is_default) await c.env.DB.prepare('UPDATE servers SET is_default = 1 WHERE id = (SELECT id FROM servers ORDER BY created_at LIMIT 1)').run();
  await audit(c.env, { actor: c.get('actor'), action: 'server.delete', server_id: row.id, detail: { name: row.name } });
  return c.json({ ok: true });
});

api.post('/servers/:id/default', async (c) => {
  const row = await loadServer(c);
  await c.env.DB.batch([c.env.DB.prepare('UPDATE servers SET is_default = 0'), c.env.DB.prepare('UPDATE servers SET is_default = 1 WHERE id = ?').bind(row.id)]);
  await audit(c.env, { actor: c.get('actor'), action: 'server.default', server_id: row.id });
  return c.json({ ok: true });
});

// Quick switch for auto-approve (server cards / Approvals page). Does not touch the SSH session.
api.post('/servers/:id/auto-approve', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, autoApproveSchema);
  const prev = normalizeLevel(row.auto_approve);
  requireAllConfirm(b.level, prev, b.confirm_text);
  await c.env.DB.prepare('UPDATE servers SET auto_approve = ?, updated_at = ? WHERE id = ?').bind(b.level, Date.now(), row.id).run();
  await audit(c.env, { actor: c.get('actor'), action: 'server.auto_approve', server_id: row.id, outcome: b.level, detail: { from: prev, to: b.level } });
  return c.json(toPublic((await getServer(c.env, row.id))!));
});

api.post('/servers/:id/connect', async (c) => {
  const row = await loadServer(c);
  const r = await sshStub(c.env, row.id).openSession(row.id);
  await audit(c.env, { actor: c.get('actor'), action: 'server.connect', server_id: row.id, outcome: r.ok ? 'ok' : r.code ?? 'error', detail: { message: r.message } });
  return c.json(r, r.ok ? 200 : 502);
});

api.post('/servers/:id/test', async (c) => {
  const row = await loadServer(c);
  const stub = sshStub(c.env, row.id);
  const r = await stub.openSession(row.id);
  if (!r.ok) return c.json(r, 502);
  const res = await stub.exec({ serverId: row.id, command: 'echo ok', timeoutMs: 15000, maxBytes: 1024, actor: c.get('actor'), classification: 'read' });
  return c.json({ ok: res.stdout.trim() === 'ok', fingerprint: r.fingerprint, latency_ms: res.durationMs });
});

api.post('/servers/:id/disconnect', async (c) => {
  const row = await loadServer(c);
  await sshStub(c.env, row.id).disconnect('manual disconnect');
  await audit(c.env, { actor: c.get('actor'), action: 'server.disconnect', server_id: row.id });
  return c.json({ ok: true });
});

api.post('/servers/:id/approve-hostkey', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, z.object({ fingerprint: z.string().min(10).max(100) }));
  if (!row.pending_fingerprint || row.pending_fingerprint !== b.fingerprint) throw new UserError('fingerprint does not match the pending host key; reconnect to capture it again', 409);
  await c.env.DB.prepare("UPDATE servers SET host_key_fingerprint = pending_fingerprint, host_key_algo = pending_fingerprint_algo, pending_fingerprint = NULL, pending_fingerprint_algo = NULL, status = 'disconnected', last_error = NULL, updated_at = ? WHERE id = ?")
    .bind(Date.now(), row.id)
    .run();
  await audit(c.env, { actor: c.get('actor'), action: 'hostkey.approve', server_id: row.id, detail: { fingerprint: b.fingerprint, algo: row.pending_fingerprint_algo } });
  return c.json({ ok: true });
});

api.get('/servers/:id/history', async (c) => {
  const row = await loadServer(c);
  const r = await c.env.DB.prepare('SELECT ts, event, detail, duration_ms FROM connection_history WHERE server_id = ? ORDER BY ts DESC LIMIT 50').bind(row.id).all();
  return c.json(r.results);
});

api.get('/servers/:id/status', async (c) => {
  const row = await loadServer(c);
  return c.json({ ...(await sshStub(c.env, row.id).status()), status: row.status, last_error: row.last_error });
});

// ---------------------------------------------------------------- terminal

api.post('/servers/:id/exec', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, execSchema.extend({ confirmed: z.boolean().optional() }));
  const settings = await getSettings(c.env);
  const d = decide(b.command, policyOf(row));
  if (d.action === 'block') {
    await audit(c.env, { actor: c.get('actor'), action: 'command.blocked', server_id: row.id, outcome: 'blocked', detail: { command: b.command, reason: d.reason } });
    return c.json({ status: 'blocked', reason: d.reason, classification: d.classification.classification }, 403);
  }
  const level = normalizeLevel(row.auto_approve);
  const a = d.action === 'confirm' && !b.confirmed ? autoApproveCommand(level, b.command, d) : null;
  const autoLevel = a && a.auto ? a.approval.level : undefined;
  if (d.action === 'confirm' && !b.confirmed && !autoLevel) {
    return c.json({ status: 'confirmation_required', reason: d.reason, classification: 'destructive', ...(a && !a.auto && a.catastrophic.length ? { catastrophic: a.catastrophic } : {}) }, 409);
  }
  if (d.action === 'confirm' && b.confirmed) await audit(c.env, { actor: c.get('actor'), action: 'command.confirmed_by_admin', server_id: row.id, detail: { command: b.command, reason: d.reason } });
  const execId = randomId('cmd_');
  const timeoutMs = Math.min(600, b.timeout_seconds ?? settings.default_command_timeout_seconds) * 1000;
  const stream = await sshStub(c.env, row.id).execStream({ serverId: row.id, command: b.command, timeoutMs, maxBytes: settings.max_output_bytes, actor: c.get('actor'), classification: d.classification.classification, resultId: execId });
  await audit(c.env, {
    actor: c.get('actor'), action: 'command.exec', server_id: row.id, auto_level: autoLevel,
    detail: { command: b.command.slice(0, 500), id: execId, classification: d.classification.classification, ...(autoLevel ? { auto_approved: true, auto_level: autoLevel, approval_reason: d.action === 'confirm' ? d.reason : undefined } : {}) },
  });
  const hdr: Record<string, string> = { 'content-type': 'application/x-ndjson; charset=utf-8', 'x-exec-id': execId, 'cache-control': 'no-store' };
  if (autoLevel) hdr['x-auto-approved'] = autoLevel;
  return new Response(stream, { headers: hdr });
});

api.post('/servers/:id/exec/:execId/cancel', async (c) => {
  const row = await loadServer(c);
  const r = await sshStub(c.env, row.id).cancel(c.req.param('execId'));
  await audit(c.env, { actor: c.get('actor'), action: 'command.cancel', server_id: row.id, detail: { id: c.req.param('execId'), found: r.ok } });
  return c.json(r);
});

api.get('/servers/:id/commands', async (c) => {
  const row = await loadServer(c);
  const r = await c.env.DB.prepare('SELECT id, actor, command, classification, status, exit_code, started_at, duration_ms FROM command_results WHERE server_id = ? ORDER BY started_at DESC LIMIT 100').bind(row.id).all();
  return c.json(r.results);
});

api.get('/commands/:id', async (c) => {
  const r = await c.env.DB.prepare('SELECT * FROM command_results WHERE id = ?').bind(c.req.param('id')).first();
  if (!r) throw new UserError('not found', 404);
  return c.json(r);
});

// ---------------------------------------------------------------- files

const qPath = (c: C) => {
  const p = c.req.query('path') ?? '';
  const r = pathSchema.safeParse(p);
  if (!r.success) throw new UserError('invalid path');
  return validateRemotePath(r.data);
};
const qInt = (c: C, k: string, d: number, max: number) => {
  const v = Number(c.req.query(k) ?? d);
  if (!Number.isInteger(v) || v < 0) throw new UserError(`invalid ${k}`);
  return Math.min(v, max);
};

api.get('/servers/:id/files', async (c) => {
  const row = await loadServer(c);
  return c.json(await sshStub(c.env, row.id).sftpList(row.id, qPath(c), qInt(c, 'offset', 0, 1e9), qInt(c, 'limit', 500, 2000) || 500));
});

api.get('/servers/:id/files/stat', async (c) => {
  const row = await loadServer(c);
  return c.json(await sshStub(c.env, row.id).sftpStat(row.id, qPath(c)));
});

api.get('/servers/:id/files/read', async (c) => {
  const row = await loadServer(c);
  const r = await sshStub(c.env, row.id).sftpRead(row.id, qPath(c), qInt(c, 'offset', 0, 1e12), Math.max(1, qInt(c, 'length', 1024 * 1024, 1024 * 1024)));
  return c.json(r);
});

api.get('/servers/:id/files/download', async (c) => {
  const row = await loadServer(c);
  const path = qPath(c);
  const { size, stream } = await sshStub(c.env, row.id).sftpDownload(row.id, path);
  await audit(c.env, { actor: c.get('actor'), action: 'file.download', server_id: row.id, detail: { path, size } });
  const name = (path.split('/').pop() || 'download').replace(/[^\w.\-]+/g, '_');
  return new Response(stream, {
    headers: { 'content-type': 'application/octet-stream', 'content-length': String(size), 'content-disposition': `attachment; filename="${name}"`, 'cache-control': 'no-store' },
  });
});

api.post('/servers/:id/files/upload', async (c) => {
  const row = await loadServer(c);
  const path = qPath(c);
  const offset = qInt(c, 'offset', 0, 1e12);
  await checkFileOp(c.env, c.get('actor'), row, 'modify', `upload ${path}`);
  const len = Number(c.req.header('content-length') ?? '0');
  if (len > MAX_UPLOAD_CHUNK) throw new UserError('chunk too large (max 8 MiB)', 413);
  const buf = new Uint8Array(await c.req.arrayBuffer());
  if (buf.length > MAX_UPLOAD_CHUNK) throw new UserError('chunk too large (max 8 MiB)', 413);
  let s = '';
  for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  const r = await sshStub(c.env, row.id).sftpWrite(row.id, path, btoa(s), offset, offset === 0);
  if (offset === 0) await audit(c.env, { actor: c.get('actor'), action: 'file.upload', server_id: row.id, detail: { path } });
  return c.json({ ok: true, bytes: r.bytes, next_offset: offset + r.bytes });
});

api.post('/servers/:id/files/write', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, z.object({ path: pathSchema, content: z.string().max(1024 * 1024) }));
  await checkFileOp(c.env, c.get('actor'), row, 'modify', `write ${b.path}`);
  const bytes = new TextEncoder().encode(b.content);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const r = await sshStub(c.env, row.id).sftpWrite(row.id, validateRemotePath(b.path), btoa(s), 0, true);
  await audit(c.env, { actor: c.get('actor'), action: 'file.write', server_id: row.id, detail: { path: b.path, bytes: r.bytes } });
  return c.json({ ok: true, bytes: r.bytes });
});

api.post('/servers/:id/files/mkdir', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, z.object({ path: pathSchema }));
  await checkFileOp(c.env, c.get('actor'), row, 'modify', `mkdir ${b.path}`);
  await sshStub(c.env, row.id).sftpMkdir(row.id, validateRemotePath(b.path));
  await audit(c.env, { actor: c.get('actor'), action: 'file.mkdir', server_id: row.id, detail: { path: b.path } });
  return c.json({ ok: true });
});

api.post('/servers/:id/files/rename', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, z.object({ from: pathSchema, to: pathSchema }));
  await checkFileOp(c.env, c.get('actor'), row, 'modify', `rename ${b.from}`);
  await sshStub(c.env, row.id).sftpRename(row.id, validateRemotePath(b.from), validateRemotePath(b.to));
  await audit(c.env, { actor: c.get('actor'), action: 'file.rename', server_id: row.id, detail: b });
  return c.json({ ok: true });
});

api.post('/servers/:id/files/delete', async (c) => {
  const row = await loadServer(c);
  const b = await body(c, z.object({ path: pathSchema, recursive: z.boolean().default(false), confirmed: z.literal(true) }));
  const o = await deleteFile(c.env, c.get('actor'), row, b.path, b.recursive, { adminConfirmed: b.confirmed });
  if (o.kind === 'blocked') return c.json({ error: o.reason }, 403);
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- confirmations

api.get('/confirmations', async (c) => {
  const status = c.req.query('status') ?? 'pending';
  const r = await c.env.DB.prepare(
    'SELECT p.id, p.server_id, s.name AS server_name, p.tool, p.operation, p.classification, p.reason, p.status, p.requested_by, p.created_at, p.expires_at, p.decided_at, p.executed_at FROM pending_confirmations p LEFT JOIN servers s ON s.id = p.server_id WHERE (?1 = \'all\' OR p.status = ?1) ORDER BY p.created_at DESC LIMIT 100',
  ).bind(status).all();
  return c.json(r.results);
});

async function decideConfirmation(c: C, approve: boolean) {
  const id = c.req.param('id');
  const r = await c.env.DB.prepare(`UPDATE pending_confirmations SET status = ?, decided_at = ? WHERE id = ? AND status = 'pending' AND expires_at > ?`).bind(approve ? 'approved' : 'rejected', Date.now(), id, Date.now()).run();
  if (!r.meta.changes) throw new UserError('confirmation not pending (expired, decided or unknown)', 409);
  await audit(c.env, { actor: c.get('actor'), action: approve ? 'confirmation.approve' : 'confirmation.reject', detail: { id } });
  return c.json({ ok: true });
}
api.post('/confirmations/approve-all', async (c) => {
  const b = await body(c, approveAllSchema);
  const now = Date.now();
  const r = await c.env.DB.prepare(
    `UPDATE pending_confirmations SET status = 'approved', decided_at = ?1 WHERE status = 'pending' AND expires_at > ?1 AND (?2 IS NULL OR server_id = ?2) RETURNING id`,
  ).bind(now, b.server_id ?? null).all<{ id: string }>();
  const ids = (r.results ?? []).map((x) => x.id);
  await audit(c.env, { actor: c.get('actor'), action: 'confirmation.approve_all', server_id: b.server_id ?? null, detail: { count: ids.length, ids: ids.slice(0, 100) } });
  return c.json({ ok: true, approved: ids.length, ids });
});
api.post('/confirmations/:id/approve', (c) => decideConfirmation(c, true));
api.post('/confirmations/:id/reject', (c) => decideConfirmation(c, false));
api.post('/confirmations/:id/token', async (c) => {
  const id = c.req.param('id');
  const token = randomToken(9);
  const r = await c.env.DB.prepare(`UPDATE pending_confirmations SET confirm_token_hash = ? WHERE id = ? AND status = 'pending' AND expires_at > ?`).bind(await sha256Hex(token), id, Date.now()).run();
  if (!r.meta.changes) throw new UserError('confirmation not pending', 409);
  await audit(c.env, { actor: c.get('actor'), action: 'confirmation.token_issued', detail: { id } });
  return c.json({ token });
});

// ---------------------------------------------------------------- MCP tokens

api.get('/mcp/tokens', async (c) => {
  const r = await c.env.DB.prepare('SELECT id, name, prefix, created_at, last_used_at, revoked_at FROM mcp_tokens ORDER BY created_at DESC').all();
  // OAuth grants (Gemini, Claude, ChatGPT, ...) are listed and revoked like tokens.
  const g = await c.env.DB.prepare(
    `SELECT 'oauth:' || g.id AS id, 'OAuth · ' || c.client_name AS name, 'oauth' AS prefix, g.created_at, g.last_used_at, g.revoked_at
     FROM oauth_grants g JOIN oauth_clients c ON c.client_id = g.client_id WHERE g.access_token_hash IS NOT NULL ORDER BY g.created_at DESC LIMIT 200`,
  ).all().catch(() => ({ results: [] as unknown[] }));
  return c.json([...g.results, ...r.results]);
});
api.post('/mcp/tokens', async (c) => {
  const b = await body(c, z.object({ name: z.string().trim().min(1).max(64) }));
  const token = MCP_TOKEN_PREFIX + randomToken(32);
  const id = randomId('tok_');
  await c.env.DB.prepare('INSERT INTO mcp_tokens (id, name, token_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?)').bind(id, b.name, await hashMcpToken(token), token.slice(0, 12), Date.now()).run();
  await audit(c.env, { actor: c.get('actor'), action: 'mcp.token_create', detail: { id, name: b.name } });
  return c.json({ id, name: b.name, token }, 201);
});
api.delete('/mcp/tokens/:id', async (c) => {
  const tid = c.req.param('id');
  if (tid.startsWith('oauth:')) {
    const r = await c.env.DB.prepare('UPDATE oauth_grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').bind(Date.now(), tid.slice(6)).run();
    if (!r.meta.changes) throw new UserError('grant not found or already revoked', 404);
    await audit(c.env, { actor: c.get('actor'), action: 'oauth.revoke', detail: { id: tid } });
    return c.json({ ok: true });
  }
  const r = await c.env.DB.prepare('UPDATE mcp_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').bind(Date.now(), c.req.param('id')).run();
  if (!r.meta.changes) throw new UserError('token not found or already revoked', 404);
  await audit(c.env, { actor: c.get('actor'), action: 'mcp.token_revoke', detail: { id: c.req.param('id') } });
  return c.json({ ok: true });
});

// ---------------------------------------------------------------- settings & audit

api.get('/settings', async (c) => c.json({ ...(await getSettings(c.env)), dev_allow_private_targets: c.env.DEV_ALLOW_PRIVATE_TARGETS === 'true', auth_mode: authMode(c.env), admin_password_source: (await adminPassword(c.env))?.source ?? null }));
api.patch('/settings', async (c) => {
  const b = await body(c, settingsSchema);
  const { default_auto_approve_confirm, ...patch } = b;
  if (patch.default_auto_approve !== undefined) requireAllConfirm(patch.default_auto_approve, (await getSettings(c.env)).default_auto_approve, default_auto_approve_confirm);
  await putSettings(c.env, patch);
  await audit(c.env, { actor: c.get('actor'), action: 'settings.update', detail: patch });
  return c.json(await getSettings(c.env));
});

api.get('/audit', async (c) => {
  const limit = Math.min(500, Number(c.req.query('limit') ?? 100) || 100);
  const before = Number(c.req.query('before') ?? 0) || Number.MAX_SAFE_INTEGER;
  const r = await c.env.DB.prepare('SELECT id, ts, actor, action, server_id, outcome, detail, ip, auto_approved, auto_level FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?').bind(before, limit).all();
  return c.json(r.results);
});

api.onError((err, c) => {
  if (err instanceof UserError) return c.json({ error: err.message }, err.status as 400);
  const msg = (err as Error).message || 'internal error';
  // RPC errors from the SSH Durable Object carry user-meaningful messages (never secrets).
  if (/^\[[A-Z_]+\]|no such file|permission denied|failure|not a regular file|path is a directory|SFTP|timed out/i.test(msg)) return c.json({ error: msg }, 502);
  console.error('api error', msg);
  return c.json({ error: 'internal error' }, 500);
});
