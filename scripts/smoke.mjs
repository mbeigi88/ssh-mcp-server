#!/usr/bin/env node
// Smoke test of a deployed instance over HTTPS. Never prints secrets.
//   BASE=https://<worker>.<subdomain>.workers.dev node scripts/smoke.mjs
//   optional: ADMIN_PASSWORD (or ADMIN_PASSWORD_FILE containing "password: <pw>") -> also logs in and reads counts
//             MCP_TOKEN -> also runs MCP initialize + tools/list
// Honors HTTPS_PROXY when undici is installed.
import fs from 'node:fs';
const BASE = (process.env.BASE ?? process.argv[2] ?? '').replace(/\/$/, '');
if (!/^https?:\/\//.test(BASE)) { console.error('usage: BASE=https://<your-worker>.workers.dev node scripts/smoke.mjs'); process.exit(2); }
if (process.env.HTTPS_PROXY) { try { const u = await import('undici'); u.setGlobalDispatcher(new u.ProxyAgent(process.env.HTTPS_PROXY)); } catch { /* direct */ } }
let pw = process.env.ADMIN_PASSWORD;
if (!pw && process.env.ADMIN_PASSWORD_FILE) pw = /password:\s*(\S+)/.exec(fs.readFileSync(process.env.ADMIN_PASSWORD_FILE, 'utf8'))?.[1];
const out = [];
let failed = 0;
const check = (name, ok, info = '') => { out.push(`${ok ? 'PASS' : 'FAIL'} ${name}${info ? ' — ' + info : ''}`); if (!ok) failed++; };

const home = await fetch(BASE + '/');
check('GET / 200 with CSP', home.status === 200 && /default-src 'none'/.test(home.headers.get('content-security-policy') ?? ''), String(home.status));
const me = await (await fetch(BASE + '/api/auth/me')).json();
check('/api/auth/me', !me.config_errors?.length, `configured=${me.configured} setup=${me.setup} auth_mode=${me.auth_mode}`);
const mcp401 = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}' });
check('/mcp without token -> 401', mcp401.status === 401, String(mcp401.status));

if (pw) {
  const r = await fetch(BASE + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: pw }) });
  check('login', r.status === 200, String(r.status));
  if (r.status === 200) {
    const cookie = r.headers.get('set-cookie').split(';')[0];
    const get = async (p) => (await fetch(BASE + '/api' + p, { headers: { cookie } })).json();
    const servers = await get('/servers');
    const audit = await get('/audit?limit=100');
    const settings = await get('/settings');
    check('servers readable', Array.isArray(servers), `count=${servers.length}`);
    check('audit readable', Array.isArray(audit), `rows(first page)=${audit.length}`);
    out.push(`INFO admin_password_source=${settings.admin_password_source}`);
  }
}
if (process.env.MCP_TOKEN) {
  const H = { authorization: 'Bearer ' + process.env.MCP_TOKEN, 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-protocol-version': '2025-06-18' };
  const init = await fetch(BASE + '/mcp', { method: 'POST', headers: H, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '1' } } }) });
  const sid = init.headers.get('mcp-session-id');
  check('MCP initialize', init.status === 200 && !!sid, String(init.status));
  await fetch(BASE + '/mcp', { method: 'POST', headers: { ...H, 'mcp-session-id': sid }, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) });
  const tl = await fetch(BASE + '/mcp', { method: 'POST', headers: { ...H, 'mcp-session-id': sid }, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) });
  const txt = await tl.text();
  let j; try { j = JSON.parse(txt); } catch { j = JSON.parse(/data: (.*)/.exec(txt)[1]); }
  check('MCP tools/list', tl.status === 200, `tools=${j.result?.tools?.length}`);
}
console.log(out.join('\n'));
process.exit(failed ? 1 : 0);
