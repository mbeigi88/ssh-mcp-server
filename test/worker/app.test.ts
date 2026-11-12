import { describe, expect, it } from 'vitest';
import { SELF, env, runInDurableObject } from 'cloudflare:test';
import { api, BASE, createMcpToken, login, mcpCall, mcpInit, mcpList, mcpRaw } from '../helpers';
import { TOOL_NAMES } from '../../src/mcp/tools';
import { decryptCredentials, getServer } from '../../src/lib/db';
import type { McpSession } from '../../src/do/mcp-session';

const ED_KEY = (JSON.parse(env.TEST_KEYS!) as Record<string, string>).id_ed25519;

describe('dashboard & security headers', () => {
  it('serves the dashboard with strict CSP and security headers', async () => {
    const r = await SELF.fetch(`${BASE}/`);
    expect(r.status).toBe(200);
    const html = await r.text();
    expect(html).toContain('<div id="app">');
    const csp = r.headers.get('content-security-policy')!;
    expect(csp).toMatch(/default-src 'none'/);
    expect(csp).toMatch(/script-src 'nonce-[\w-]+'/);
    expect(csp).toMatch(/frame-ancestors 'none'/);
    const nonce = /nonce-([\w-]+)/.exec(csp)![1];
    expect(html).toContain(`<script nonce="${nonce}">`);
    expect(r.headers.get('strict-transport-security')).toMatch(/max-age=\d+/);
    expect(r.headers.get('x-frame-options')).toBe('DENY');
    expect(r.headers.get('x-content-type-options')).toBe('nosniff');
    expect(r.headers.get('referrer-policy')).toBe('no-referrer');
  });
  it('serves the same-origin Vazirmatn font and keeps the page free of inline style/handler attributes', async () => {
    const f = await SELF.fetch(`${BASE}/assets/vazirmatn.woff2`);
    expect(f.status).toBe(200);
    expect(f.headers.get('content-type')).toBe('font/woff2');
    expect(f.headers.get('x-content-type-options')).toBe('nosniff');
    const buf = new Uint8Array(await f.arrayBuffer());
    expect(String.fromCharCode(...buf.slice(0, 4))).toBe('wOF2');
    const r = await SELF.fetch(`${BASE}/`);
    const csp = r.headers.get('content-security-policy')!;
    expect(csp).toMatch(/font-src 'self'/);
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval/);
    const html = await r.text();
    expect(html).not.toMatch(/\sstyle="/);
    expect(html).not.toMatch(/\son[a-z]+="/);
    expect((html.match(/<script/g) ?? []).length).toBe(1);
  });
  it('api responses also carry security headers and no-store', async () => {
    const r = await SELF.fetch(`${BASE}/api/auth/me`);
    expect(r.headers.get('x-frame-options')).toBe('DENY');
    expect(r.headers.get('cache-control')).toBe('no-store');
  });
});

describe('dashboard authentication', () => {
  it('rejects unauthenticated API access', async () => {
    expect((await api(null, 'GET', '/servers')).status).toBe(401);
    expect((await api(null, 'GET', '/overview')).status).toBe(401);
  });
  it('reports configured / unauthenticated state', async () => {
    const r = await api(null, 'GET', '/auth/me');
    expect(r.json).toMatchObject({ authenticated: false, configured: true, auth_mode: 'password' });
  });
  it('rejects a wrong password and accepts the right one with a hardened cookie', async () => {
    const bad = await SELF.fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.9' }, body: JSON.stringify({ password: 'nope' }) });
    expect(bad.status).toBe(401);
    const ok = await SELF.fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.9' }, body: JSON.stringify({ password: env.TEST_ADMIN_PASSWORD }) });
    expect(ok.status).toBe(200);
    const sc = ok.headers.get('set-cookie')!;
    expect(sc).toMatch(/^__Host-sshmcp_session=/);
    expect(sc).toMatch(/HttpOnly/);
    expect(sc).toMatch(/Secure/);
    expect(sc).toMatch(/SameSite=Strict/);
    expect(sc).toMatch(/Path=\//);
  });
  it('rate-limits login attempts per IP', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) {
      const r = await SELF.fetch(`${BASE}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.77' }, body: JSON.stringify({ password: 'wrong' }) });
      statuses.push(r.status);
    }
    expect(statuses.slice(0, 5).every((s) => s === 401)).toBe(true);
    expect(statuses[5]).toBe(429);
  });
  it('requires a CSRF token on state-changing requests', async () => {
    const auth = await login();
    const noCsrf = await SELF.fetch(`${BASE}/api/mcp/tokens`, { method: 'POST', headers: { cookie: auth.cookie, 'content-type': 'application/json' }, body: '{"name":"x"}' });
    expect(noCsrf.status).toBe(403);
    const wrong = await api({ ...auth, csrf: 'forged' }, 'POST', '/mcp/tokens', { name: 'x' });
    expect(wrong.status).toBe(403);
    const crossOrigin = await api(auth, 'POST', '/mcp/tokens', { name: 'x' }, { origin: 'https://evil.example' });
    expect(crossOrigin.status).toBe(403);
    const good = await api(auth, 'POST', '/mcp/tokens', { name: 'x' });
    expect(good.status).toBe(201);
  });
  it('expires sessions', async () => {
    const auth = await login();
    expect((await api(auth, 'GET', '/servers')).status).toBe(200);
    await env.DB.prepare('UPDATE sessions SET expires_at = ?').bind(Date.now() - 1000).run();
    expect((await api(auth, 'GET', '/servers')).status).toBe(401);
  });
  it('logout invalidates the session', async () => {
    const auth = await login();
    expect((await api(auth, 'POST', '/auth/logout')).status).toBe(200);
    expect((await api(auth, 'GET', '/servers')).status).toBe(401);
  });
});

describe('server management & credential secrecy', () => {
  it('creates, edits and deletes servers without ever returning secrets', async () => {
    const auth = await login();
    const created = await api(auth, 'POST', '/servers', { name: 'prod', host: 'example.com', port: 22, username: 'deploy', auth_method: 'password', password: 'Sup3r-Secret-PW', labels: ['web', 'eu'] });
    expect(created.status).toBe(201);
    const body = JSON.stringify(created.json);
    expect(body).not.toContain('Sup3r-Secret-PW');
    expect(created.json.password).toBe('set');
    expect(created.json.is_default).toBe(true);
    const row = (await getServer(env, created.json.id))!;
    expect(row.cred_ciphertext).toBeTruthy();
    expect(row.cred_ciphertext).not.toContain('Sup3r');
    // update without password keeps credentials
    const upd = await api(auth, 'PATCH', `/servers/${created.json.id}`, { name: 'prod-1', labels: ['web'] });
    expect(upd.status).toBe(200);
    expect(upd.json.name).toBe('prod-1');
    expect((await decryptCredentials(env, (await getServer(env, created.json.id))!)).password).toBe('Sup3r-Secret-PW');
    // switch to key auth
    const k = await api(auth, 'PATCH', `/servers/${created.json.id}`, { auth_method: 'key', private_key: ED_KEY });
    expect(k.status).toBe(200);
    expect(JSON.stringify(k.json)).not.toContain('OPENSSH');
    expect(k.json.private_key).toBe('set');
    // list / overview / audit contain no secrets
    for (const p of ['/servers', '/overview', '/audit']) {
      const r = await api(auth, 'GET', p);
      expect(JSON.stringify(r.json)).not.toMatch(/Sup3r-Secret-PW|BEGIN OPENSSH/);
    }
    expect((await api(auth, 'DELETE', `/servers/${created.json.id}`)).status).toBe(200);
    expect((await api(auth, 'GET', `/servers/${created.json.id}`)).status).toBe(404);
  });
  it('validates input and requires explicit root opt-in', async () => {
    const auth = await login();
    expect((await api(auth, 'POST', '/servers', { name: 'r', host: 'example.com', username: 'root', auth_method: 'password', password: 'x' })).status).toBe(400);
    expect((await api(auth, 'POST', '/servers', { name: 'r', host: 'bad host!', username: 'u', auth_method: 'password', password: 'x' })).status).toBe(400);
    expect((await api(auth, 'POST', '/servers', { name: 'r', host: 'example.com', username: 'u', auth_method: 'key', private_key: 'garbage' })).status).toBe(400);
    const r = await api(auth, 'POST', '/servers', { name: 'r', host: 'example.com', username: 'root', allow_root: true, auth_method: 'password', password: 'x' });
    expect(r.status).toBe(201);
    expect((await api(auth, 'POST', '/servers', { name: 'r', host: 'example.com', username: 'u', auth_method: 'password', password: 'x' })).status).toBe(409);
  });
  it('blocks SSRF targets (loopback, metadata, private) at connect time', async () => {
    const auth = await login();
    for (const host of ['127.0.0.1', '169.254.169.254', '10.0.0.1', 'localhost', '::1']) {
      const s = await api(auth, 'POST', '/servers', { name: `ssrf-${host}`, host, username: 'u', auth_method: 'password', password: 'x' });
      expect(s.status).toBe(201);
      const c = await api(auth, 'POST', `/servers/${s.json.id}/connect`);
      expect(c.status).toBe(502);
      expect(c.json.code).toBe('TARGET_BLOCKED');
    }
  });
});

describe('MCP endpoint', () => {
  it('requires a valid bearer token', async () => {
    const r = await mcpRaw(null, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toMatch(/Bearer/);
    expect((await mcpRaw('sshmcp_invalid', { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })).status).toBe(401);
  });

  it('initializes, lists all tools with schemas, and calls tools', async () => {
    const auth = await login();
    const { token } = await createMcpToken(auth);
    expect(token).toMatch(/^sshmcp_/);
    const stored = await env.DB.prepare('SELECT token_hash FROM mcp_tokens').all<{ token_hash: string }>();
    expect(JSON.stringify(stored.results)).not.toContain(token);
    const init = await mcpRaw(token, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
    expect(init.status).toBe(200);
    expect(init.json.result.serverInfo.name).toBe('my-ssh-mcp');
    expect(init.json.result.capabilities.tools).toBeDefined();
    const sid = init.headers.get('mcp-session-id')!;
    expect(sid).toMatch(/^[0-9a-f-]{36}$/);
    await mcpRaw(token, { jsonrpc: '2.0', method: 'notifications/initialized' }, sid);
    const list = await mcpList(token, sid);
    const names = list.json.result.tools.map((t: { name: string }) => t.name).sort();
    expect(names).toEqual([...TOOL_NAMES].sort());
    for (const t of list.json.result.tools) {
      expect(t.description.length).toBeGreaterThan(10);
      expect(t.inputSchema.type).toBe('object');
    }
    const exec = list.json.result.tools.find((t: { name: string }) => t.name === 'execute_command');
    expect(exec.inputSchema.required).toContain('command');

    const ls = await mcpCall(token, sid, 'list_servers');
    expect(Array.isArray(ls.data)).toBe(true);
  });

  it('returns JSON-RPC errors for bad requests and unknown sessions', async () => {
    const auth = await login();
    const { token } = await createMcpToken(auth);
    const sid = await mcpInit(token);
    const unknownTool = await mcpRaw(token, { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'nope', arguments: {} } }, sid);
    expect(JSON.stringify(unknownTool.json)).toMatch(/nope|not found|error/i);
    const badMethod = await mcpRaw(token, { jsonrpc: '2.0', id: 10, method: 'does/not/exist' }, sid);
    expect(badMethod.json.error.code).toBe(-32601);
    const badArgs = await mcpRaw(token, { jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'execute_command', arguments: { command: 123 } } }, sid);
    expect(JSON.stringify(badArgs.json)).toMatch(/invalid|error/i);
    const unknownSession = await mcpRaw(token, { jsonrpc: '2.0', id: 12, method: 'tools/list' }, '00000000-0000-4000-8000-000000000000');
    expect(unknownSession.status).toBe(404);
  });

  it('supports multiple concurrent clients, binds sessions to tokens, and handles revocation', async () => {
    const auth = await login();
    const a = await createMcpToken(auth, 'a');
    const b = await createMcpToken(auth, 'b');
    const sa = await mcpInit(a.token);
    const sb = await mcpInit(b.token);
    expect(sa).not.toBe(sb);
    expect((await mcpList(a.token, sa)).status).toBe(200);
    expect((await mcpList(b.token, sb)).status).toBe(200);
    expect((await mcpList(b.token, sa)).status).toBe(403); // token b cannot hijack session a
    expect((await api(auth, 'DELETE', `/mcp/tokens/${a.id}`)).status).toBe(200);
    expect((await mcpList(a.token, sa)).status).toBe(401);
  });

  it('restores a session after Durable Object eviction, and terminates on DELETE', async () => {
    const auth = await login();
    const { token } = await createMcpToken(auth);
    const sid = await mcpInit(token);
    const stub = env.MCP_SESSION.get(env.MCP_SESSION.idFromName(sid));
    await runInDurableObject(stub, async (inst: McpSession) => { await inst.dropMemoryForTests(); });
    const after = await mcpList(token, sid);
    expect(after.status).toBe(200);
    expect(after.json.result.tools.length).toBe(TOOL_NAMES.length);
    const del = await mcpRaw(token, undefined, sid, 'DELETE');
    expect(del.status).toBe(200);
    const gone = await mcpList(token, sid);
    expect(gone.status).toBe(404);
  });

  it('destructive commands require human confirmation before any SSH happens', async () => {
    const auth = await login();
    await api(auth, 'POST', '/servers', { name: 'confirm-srv', host: 'example.com', username: 'deploy', auth_method: 'password', password: 'x' });
    const { token } = await createMcpToken(auth);
    const sid = await mcpInit(token);
    const r = await mcpCall(token, sid, 'execute_command', { server: 'confirm-srv', command: 'rm -rf /var/www' });
    expect(r.data.status).toBe('confirmation_required');
    expect(r.data.confirmation_id).toMatch(/^cfm_/);
    // calling with the id before approval is refused
    const early = await mcpCall(token, sid, 'execute_command', { server: 'confirm-srv', command: 'x', confirmation_id: r.data.confirmation_id });
    expect(early.isError).toBe(true);
    expect(early.text).toMatch(/still pending/);
    // a guessed confirm token is refused
    const guess = await mcpCall(token, sid, 'execute_command', { server: 'confirm-srv', command: 'x', confirmation_id: r.data.confirmation_id, confirm_token: 'guess' });
    expect(guess.text).toMatch(/invalid confirmation token/);
    const pend = await api(auth, 'GET', '/confirmations?status=pending');
    expect(pend.json.some((p: { id: string }) => p.id === r.data.confirmation_id)).toBe(true);
    // reject
    expect((await api(auth, 'POST', `/confirmations/${r.data.confirmation_id}/reject`)).status).toBe(200);
    const after = await mcpCall(token, sid, 'execute_command', { server: 'confirm-srv', command: 'x', confirmation_id: r.data.confirmation_id });
    expect(after.text).toMatch(/rejected/);
    // read-only mode blocks modify commands outright
    const srv = (await api(auth, 'GET', '/servers')).json.find((s: { name: string }) => s.name === 'confirm-srv');
    await api(auth, 'PATCH', `/servers/${srv.id}`, { policy_mode: 'read_only' });
    const blocked = await mcpCall(token, sid, 'execute_command', { server: 'confirm-srv', command: 'touch /tmp/x' });
    expect(blocked.isError).toBe(true);
    expect(blocked.data.status).toBe('blocked');
    const del = await mcpCall(token, sid, 'delete_file', { server: 'confirm-srv', path: '/tmp/x' });
    expect(del.data.status).toBe('blocked');
  });
});
