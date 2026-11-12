import { SELF, env } from 'cloudflare:test';

export const BASE = 'https://ssh-mcp.test';
let ipCounter = 1;

export interface Auth { cookie: string; csrf: string }

export async function login(password = env.TEST_ADMIN_PASSWORD): Promise<Auth> {
  const r = await SELF.fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': `198.51.100.${ipCounter++ % 250}` },
    body: JSON.stringify({ password }),
  });
  if (r.status !== 200) throw new Error(`login failed ${r.status} ${await r.text()}`);
  const setCookie = r.headers.get('set-cookie')!;
  const j = (await r.json()) as { csrf: string };
  return { cookie: setCookie.split(';')[0], csrf: j.csrf };
}

export async function api(auth: Auth | null, method: string, path: string, body?: unknown, extra: Record<string, string> = {}) {
  const headers: Record<string, string> = { ...extra };
  if (auth) { headers.cookie = auth.cookie; if (method !== 'GET') headers['x-csrf-token'] = auth.csrf; }
  if (body !== undefined) headers['content-type'] = 'application/json';
  const r = await SELF.fetch(`${BASE}/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, json, headers: r.headers };
}

export async function createMcpToken(auth: Auth, name = 'test'): Promise<{ id: string; token: string }> {
  const r = await api(auth, 'POST', '/mcp/tokens', { name });
  if (r.status !== 201) throw new Error('token create failed ' + JSON.stringify(r.json));
  return r.json;
}

let rpcId = 1;
export async function mcpRaw(token: string | null, body: unknown, sessionId?: string, method = 'POST') {
  const headers: Record<string, string> = { accept: 'application/json, text/event-stream', 'content-type': 'application/json', 'mcp-protocol-version': '2025-06-18' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (sessionId) headers['mcp-session-id'] = sessionId;
  const r = await SELF.fetch(`${BASE}/mcp`, { method, headers, body: method === 'POST' ? JSON.stringify(body) : undefined });
  const text = await r.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, json, headers: r.headers };
}

export async function mcpInit(token: string): Promise<string> {
  const r = await mcpRaw(token, {
    jsonrpc: '2.0', id: rpcId++, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'vitest', version: '1' } },
  });
  if (r.status !== 200) throw new Error('init failed ' + r.status + ' ' + JSON.stringify(r.json));
  const sid = r.headers.get('mcp-session-id')!;
  await mcpRaw(token, { jsonrpc: '2.0', method: 'notifications/initialized' }, sid);
  return sid;
}

export async function mcpCall(token: string, sid: string, name: string, args: Record<string, unknown> = {}) {
  const r = await mcpRaw(token, { jsonrpc: '2.0', id: rpcId++, method: 'tools/call', params: { name, arguments: args } }, sid);
  if (r.status !== 200) throw new Error(`tools/call ${name} -> HTTP ${r.status} ${JSON.stringify(r.json)}`);
  const res = r.json.result;
  if (!res) throw new Error(`tools/call ${name} -> ${JSON.stringify(r.json)}`);
  const text: string = res.content?.[0]?.text ?? '';
  let data: any = text;
  try { data = JSON.parse(text); } catch { /* text */ }
  return { isError: !!res.isError, data, text };
}

export async function mcpList(token: string, sid: string) {
  const r = await mcpRaw(token, { jsonrpc: '2.0', id: rpcId++, method: 'tools/list', params: {} }, sid);
  return r;
}
