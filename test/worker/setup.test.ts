import { beforeEach, describe, expect, it } from 'vitest';
import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import app from '../../src/index';
import { hashPassword } from '../../src/lib/crypto';

// These tests call the app directly with a modified env, so one Worker config can exercise fresh deployments
// (no ADMIN_PASSWORD_HASH), weak secrets, and the precedence rules.
const BASE = 'https://ssh-mcp.test';
const SETUP_TOKEN = 'correct horse battery staple';
const fresh = { ...env, ADMIN_PASSWORD_HASH: undefined, SETUP_TOKEN } as typeof env;
let ip = 1;

async function call(e: typeof env, method: string, path: string, opts: { body?: unknown; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { 'cf-connecting-ip': `192.0.2.${ip}`, ...(opts.headers ?? {}) };
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  const ctx = createExecutionContext();
  const r = await app.fetch(new Request(BASE + path, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) }), e, ctx);
  await waitOnExecutionContext(ctx);
  const text = await r.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, json, headers: r.headers };
}

/** GET /api/setup -> { csrf, cookie } */
async function setupCsrf(e: typeof env) {
  const r = await call(e, 'GET', '/api/setup');
  expect(r.json.state).toBe('available');
  const cookie = r.headers.get('set-cookie')!.split(';')[0];
  return { csrf: r.json.csrf as string, cookie };
}
async function postSetup(e: typeof env, body: unknown, s?: { csrf: string; cookie: string }, extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra };
  if (s) { headers.cookie = s.cookie; headers['x-csrf-token'] = s.csrf; }
  return call(e, 'POST', '/api/setup', { body, headers });
}

beforeEach(async () => {
  ip++;
  await env.DB.prepare("DELETE FROM settings WHERE key LIKE 'secret:%'").run();
  await env.DB.prepare('DELETE FROM rate_limits').run();
});

describe('first-run setup', () => {
  it('reports setup available on a fresh deployment and needs_token without SETUP_TOKEN', async () => {
    const me = await call(fresh, 'GET', '/api/auth/me');
    expect(me.json).toMatchObject({ authenticated: false, configured: false, setup: 'available', config_errors: [] });
    const noTok = await call({ ...fresh, SETUP_TOKEN: undefined } as typeof env, 'GET', '/api/auth/me');
    expect(noTok.json).toMatchObject({ setup: 'needs_token', setup_reason: 'setup_token_missing' });
    const shortTok = await call({ ...fresh, SETUP_TOKEN: 'short' } as typeof env, 'GET', '/api/auth/me');
    expect(shortTok.json).toMatchObject({ setup: 'needs_token', setup_reason: 'setup_token_too_short' });
    // without a token the POST is refused outright
    const s = await postSetup({ ...fresh, SETUP_TOKEN: undefined } as typeof env, { setup_token: 'x', password: 'whatever-password-1' });
    expect(s.status).toBe(403);
  });

  it('requires the CSRF double-submit token and a same-origin Origin', async () => {
    const s = await setupCsrf(fresh);
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'a-good-admin-pass-1' })).status).toBe(403);
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'a-good-admin-pass-1' }, { ...s, csrf: 'forged' })).status).toBe(403);
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'a-good-admin-pass-1' }, s, { origin: 'https://evil.example' })).status).toBe(403);
    expect((await call(fresh, 'GET', '/api/auth/me')).json.setup).toBe('available');
  });

  it('rejects a wrong setup token and weak passwords', async () => {
    const s = await setupCsrf(fresh);
    const wrong = await postSetup(fresh, { setup_token: 'not the right token', password: 'a-good-admin-pass-1' }, s);
    expect(wrong.status).toBe(401);
    expect(wrong.json.error).toMatch(/wrong setup token/);
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'short' }, s)).status).toBe(400);
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'aaaaaaaaaaaaaaaa' }, s)).status).toBe(400);
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: SETUP_TOKEN }, s)).status).toBe(400);
    const audit = await env.DB.prepare("SELECT count(*) AS n FROM audit_log WHERE action = 'auth.setup' AND outcome = 'denied'").first<{ n: number }>();
    expect(audit!.n).toBeGreaterThan(0);
  });

  it('rate-limits setup attempts per IP', async () => {
    const s = await setupCsrf(fresh);
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await postSetup(fresh, { setup_token: `wrong-token-${i}-xx`, password: 'a-good-admin-pass-1' }, s)).status);
    expect(statuses.slice(0, 5).every((x) => x === 401)).toBe(true);
    expect(statuses[5]).toBe(429);
    // even the right token is refused while rate-limited
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'a-good-admin-pass-1' }, s)).status).toBe(429);
  });

  it('creates the admin password, logs in, and is permanently disabled afterwards', async () => {
    const s = await setupCsrf(fresh);
    const ok = await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'my-new-admin-pass-1' }, s);
    expect(ok.status).toBe(200);
    expect(ok.json.csrf).toBeTruthy();
    expect(ok.headers.get('set-cookie')).toMatch(/__Host-sshmcp_session=/);
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    expect((await call(fresh, 'GET', '/api/servers', { headers: { cookie } })).status).toBe(200);
    // stored as a PBKDF2 hash in D1, never in plain text
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'secret:admin_password_hash_local'").first<{ value: string }>();
    expect(row!.value).toMatch(/^pbkdf2\$sha256\$100000\$/);
    expect(row!.value).not.toContain('my-new-admin-pass-1');
    // setup is now disabled: state done, GET gives no csrf, POST refused even with the right token
    expect((await call(fresh, 'GET', '/api/auth/me')).json).toMatchObject({ setup: 'done', configured: true });
    expect((await call(fresh, 'GET', '/api/setup')).json).toMatchObject({ state: 'done', csrf: null });
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'attacker-password-9' }, s)).status).toBe(403);
    // login with the new password works
    const login = await call(fresh, 'POST', '/api/auth/login', { body: { password: 'my-new-admin-pass-1' } });
    expect(login.status).toBe(200);
    // even if the stored hash disappears, setup stays locked (no re-claiming)
    await env.DB.prepare("DELETE FROM settings WHERE key = 'secret:admin_password_hash_local'").run();
    expect((await call(fresh, 'GET', '/api/auth/me')).json.setup).toBe('locked');
    expect((await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'attacker-password-9' }, s)).status).toBe(403);
  });

  it('two racing setup requests cannot both succeed', async () => {
    const s = await setupCsrf(fresh);
    const [a, b] = await Promise.all([
      postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'racer-one-password' }, s),
      postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'racer-two-password' }, s),
    ]);
    expect([a.status, b.status].sort()).toEqual([200, 403]);
  });

  it('the ADMIN_PASSWORD_HASH secret disables setup and takes precedence over a D1 password', async () => {
    // secret present -> no setup at all
    expect((await call(env, 'GET', '/api/auth/me')).json.setup).toBe('done');
    expect((await call(env, 'GET', '/api/setup')).json.state).toBe('done');
    // a D1 password created by setup is overridden once the secret is set (recovery path)
    await env.DB.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('secret:admin_password_hash_local', ?, 0)").bind(await hashPassword('d1-stored-password')).run();
    expect((await call(env, 'POST', '/api/auth/login', { body: { password: 'd1-stored-password' } })).status).toBe(401);
    const ok = await call(env, 'POST', '/api/auth/login', { body: { password: env.TEST_ADMIN_PASSWORD } });
    expect(ok.status).toBe(200);
    // change-password is refused while the password comes from the secret, with an explanation
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const settings = await call(env, 'GET', '/api/settings', { headers: { cookie } });
    expect(settings.json.admin_password_source).toBe('secret');
    const ch = await call(env, 'POST', '/api/auth/change-password', { body: { current_password: env.TEST_ADMIN_PASSWORD, new_password: 'another-password-1' }, headers: { cookie, 'x-csrf-token': ok.json.csrf } });
    expect(ch.status).toBe(409);
    expect(ch.json.error).toMatch(/ADMIN_PASSWORD_HASH/);
  });

  it('keeps v1 behaviour: a password changed in the v1 dashboard (legacy D1 key) still overrides the secret', async () => {
    await env.DB.prepare("INSERT INTO settings (key, value, updated_at) VALUES ('secret:admin_password_hash', ?, 0)").bind(await hashPassword('changed-in-v1-dash')).run();
    expect((await call(env, 'POST', '/api/auth/login', { body: { password: env.TEST_ADMIN_PASSWORD } })).status).toBe(401);
    const ok = await call(env, 'POST', '/api/auth/login', { body: { password: 'changed-in-v1-dash' } });
    expect(ok.status).toBe(200);
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const ch = await call(env, 'POST', '/api/auth/change-password', { body: { current_password: 'changed-in-v1-dash', new_password: 'changed-again-now-1' }, headers: { cookie, 'x-csrf-token': ok.json.csrf } });
    expect(ch.status).toBe(200);
    expect((await call(env, 'POST', '/api/auth/login', { body: { password: 'changed-again-now-1' } })).status).toBe(200);
  });

  it('a D1-stored password can be changed from Settings', async () => {
    const s = await setupCsrf(fresh);
    const ok = await postSetup(fresh, { setup_token: SETUP_TOKEN, password: 'first-admin-pass-1' }, s);
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    expect((await call(fresh, 'GET', '/api/settings', { headers: { cookie } })).json.admin_password_source).toBe('d1');
    const h = { cookie, 'x-csrf-token': ok.json.csrf };
    expect((await call(fresh, 'POST', '/api/auth/change-password', { body: { current_password: 'wrong-current-pw', new_password: 'second-admin-pass-2' }, headers: h })).status).toBe(403);
    expect((await call(fresh, 'POST', '/api/auth/change-password', { body: { current_password: 'first-admin-pass-1', new_password: 'second-admin-pass-2' }, headers: h })).status).toBe(200);
    expect((await call(fresh, 'POST', '/api/auth/login', { body: { password: 'first-admin-pass-1' } })).status).toBe(401);
    expect((await call(fresh, 'POST', '/api/auth/login', { body: { password: 'second-admin-pass-2' } })).status).toBe(200);
  });
});

describe('secret configuration checks', () => {
  it('weak or missing secrets give a clear error instead of a crash', async () => {
    for (const bad of [{ ENCRYPTION_KEY: '' }, { ENCRYPTION_KEY: 'too-short' }, { ENCRYPTION_KEY: 'a'.repeat(40) }, { SESSION_SECRET: 'short' }, { SESSION_SECRET: undefined }]) {
      const e = { ...env, ...bad } as typeof env;
      const me = await call(e, 'GET', '/api/auth/me');
      expect(me.status).toBe(200);
      expect(me.json.config_errors.length).toBeGreaterThan(0);
      const login = await call(e, 'POST', '/api/auth/login', { body: { password: env.TEST_ADMIN_PASSWORD } });
      expect(login.status).toBe(503);
      expect(login.json.error).toMatch(/not configured/);
      const mcp = await call(e, 'POST', '/mcp', { body: { jsonrpc: '2.0', id: 1, method: 'initialize' }, headers: { authorization: 'Bearer sshmcp_x' } });
      expect(mcp.status).toBe(503);
      expect((await call(e, 'GET', '/')).status).toBe(200); // the page itself renders and explains
    }
  });

  it('passphrase secrets work end to end (store + decrypt a server credential)', async () => {
    const e = { ...env, ENCRYPTION_KEY: 'six random words make a fine passphrase here', SESSION_SECRET: 'another long passphrase for the sessions!' } as typeof env;
    expect((await call(e, 'GET', '/api/auth/me')).json.config_errors).toEqual([]);
    const ok = await call(e, 'POST', '/api/auth/login', { body: { password: env.TEST_ADMIN_PASSWORD } });
    expect(ok.status).toBe(200);
    const h = { cookie: ok.headers.get('set-cookie')!.split(';')[0], 'x-csrf-token': ok.json.csrf };
    const created = await call(e, 'POST', '/api/servers', { body: { name: 'pp', host: 'example.com', username: 'u', auth_method: 'password', password: 'pp-secret-1' }, headers: h });
    expect(created.status).toBe(201);
    const { decryptCredentials, getServer } = await import('../../src/lib/db');
    expect((await decryptCredentials(e, (await getServer(e, created.json.id))!)).password).toBe('pp-secret-1');
    await expect(decryptCredentials(env, (await getServer(env, created.json.id))!)).rejects.toThrow(/decryption failed/);
    await call(e, 'DELETE', `/api/servers/${created.json.id}`, { headers: h });
  });
});
