import { describe, expect, it } from 'vitest';
import { SELF, env } from 'cloudflare:test';
import { BASE, api, login, mcpInit } from '../helpers';

const REDIRECT = 'https://gemini.google.com/mcp/oauth/callback';
let ip = 1;
const hdr = () => ({ 'cf-connecting-ip': `203.0.113.${ip++ % 250}` });

function b64url(buf: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return { verifier, challenge };
}
async function register(extra: Record<string, unknown> = {}) {
  const r = await SELF.fetch(`${BASE}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...hdr() },
    body: JSON.stringify({ client_name: 'Gemini', redirect_uris: [REDIRECT], ...extra }),
  });
  return { status: r.status, json: (await r.json()) as any };
}
async function authorize(clientId: string, challenge: string, password: string, decision = 'approve') {
  const q = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', scope: 'mcp' });
  const page = await SELF.fetch(`${BASE}/oauth/authorize?${q}`, { headers: hdr() });
  expect(page.status).toBe(200);
  expect(page.headers.get('content-security-policy')).toContain("form-action 'self' https://gemini.google.com");
  const html = await page.text();
  const form = new URLSearchParams();
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) form.set(m[1], m[2].replace(/&amp;/g, '&'));
  form.set('password', password);
  form.set('decision', decision);
  return SELF.fetch(`${BASE}/oauth/authorize`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: BASE, ...hdr() }, body: form });
}
async function token(body: Record<string, string>) {
  const r = await SELF.fetch(`${BASE}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...hdr() }, body: new URLSearchParams(body) });
  return { status: r.status, json: (await r.json()) as any };
}

describe('OAuth 2.1 for MCP clients', () => {
  it('publishes discovery metadata and points 401s at it', async () => {
    const pr = await (await SELF.fetch(`${BASE}/.well-known/oauth-protected-resource`)).json<any>();
    expect(pr.resource).toBe(`${BASE}/mcp`);
    expect(pr.authorization_servers).toEqual([BASE]);
    const as = await (await SELF.fetch(`${BASE}/.well-known/oauth-authorization-server`)).json<any>();
    expect(as.code_challenge_methods_supported).toEqual(['S256']);
    expect(as.registration_endpoint).toBe(`${BASE}/oauth/register`);
    const r = await SELF.fetch(`${BASE}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource"`);
  });

  it('rejects dangerous redirect URIs at registration', async () => {
    expect((await register({ redirect_uris: ['javascript:alert(1)'] })).status).toBe(400);
    expect((await register({ redirect_uris: ['http://evil.example/cb'] })).status).toBe(400);
    expect((await register({ redirect_uris: ['http://127.0.0.1:33418/cb'] })).status).toBe(201);
  });

  it('full flow: register, approve with password, PKCE token, call MCP, refresh, revoke', async () => {
    const reg = await register();
    expect(reg.status).toBe(201);
    const { verifier, challenge } = await pkce();

    const bad = await authorize(reg.json.client_id, challenge, 'wrong-password');
    expect(bad.status).toBe(401);

    const ok = await authorize(reg.json.client_id, challenge, env.TEST_ADMIN_PASSWORD);
    expect(ok.status).toBe(302);
    const loc = new URL(ok.headers.get('location')!);
    expect(loc.origin + loc.pathname).toBe(REDIRECT);
    expect(loc.searchParams.get('state')).toBe('xyz');
    expect(loc.searchParams.get('iss')).toBe(BASE);
    const code = loc.searchParams.get('code')!;

    const wrongVerifier = await token({ grant_type: 'authorization_code', code, code_verifier: 'x'.repeat(43), client_id: reg.json.client_id, redirect_uri: REDIRECT });
    expect(wrongVerifier.status).toBe(400);
    // the code was consumed by the failed attempt
    const replay = await token({ grant_type: 'authorization_code', code, code_verifier: verifier, client_id: reg.json.client_id, redirect_uri: REDIRECT });
    expect(replay.json.error).toBe('invalid_grant');

    const { challenge: c2, verifier: v2 } = await pkce();
    const ok2 = await authorize(reg.json.client_id, c2, env.TEST_ADMIN_PASSWORD);
    const code2 = new URL(ok2.headers.get('location')!).searchParams.get('code')!;
    const t = await token({ grant_type: 'authorization_code', code: code2, code_verifier: v2, client_id: reg.json.client_id, redirect_uri: REDIRECT });
    expect(t.status).toBe(200);
    expect(t.json.token_type).toBe('Bearer');
    expect(t.json.access_token).toMatch(/^sshmcp_oat_/);

    const sid = await mcpInit(t.json.access_token);
    expect(sid).toMatch(/^[0-9a-f-]{36}$/);

    const rt = await token({ grant_type: 'refresh_token', refresh_token: t.json.refresh_token, client_id: reg.json.client_id });
    expect(rt.status).toBe(200);
    expect(rt.json.access_token).not.toBe(t.json.access_token);
    // old refresh token rotated out
    expect((await token({ grant_type: 'refresh_token', refresh_token: t.json.refresh_token, client_id: reg.json.client_id })).status).toBe(400);

    // listed + revocable from the dashboard
    const auth = await login();
    const list = await api(auth, 'GET', '/mcp/tokens');
    const g = list.json.find((x: any) => x.prefix === 'oauth' && !x.revoked_at);
    expect(g.name).toBe('OAuth · Gemini');
    expect((await api(auth, 'DELETE', `/mcp/tokens/${g.id}`)).status).toBe(200);
    const after = await SELF.fetch(`${BASE}/mcp`, { method: 'POST', headers: { authorization: `Bearer ${rt.json.access_token}`, 'content-type': 'application/json' }, body: '{}' });
    expect(after.status).toBe(401);
  });

  it('deny redirects with access_denied', async () => {
    const reg = await register();
    const { challenge } = await pkce();
    const r = await authorize(reg.json.client_id, challenge, '', 'deny');
    expect(r.status).toBe(302);
    expect(new URL(r.headers.get('location')!).searchParams.get('error')).toBe('access_denied');
  });
});
