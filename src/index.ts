import './ssh/crypto-polyfill';
import { Hono } from 'hono';
import type { Env } from './env';
import { api } from './api/routes';
import { renderDashboard } from './ui/dashboard';
import { clientIp, verifyMcpBearer } from './lib/auth';
import { rateLimit } from './lib/ratelimit';
import { audit } from './lib/db';
import { jsonRpcError } from './do/mcp-session';
import { randomToken } from './lib/crypto';
import { VAZIRMATN_WOFF2_B64 } from './ui/font';
import { configIssues, describeIssues } from './lib/config';

let fontBytes: Uint8Array | null = null;
function vazirmatn(): Uint8Array {
  if (!fontBytes) fontBytes = Uint8Array.from(atob(VAZIRMATN_WOFF2_B64), (ch) => ch.charCodeAt(0));
  return fontBytes;
}

export { SshSession } from './do/ssh-session';
export { McpSession } from './do/mcp-session';

const app = new Hono<{ Bindings: Env }>();

function securityHeaders(h: Headers, nonce?: string) {
  h.set(
    'content-security-policy',
    [
      "default-src 'none'",
      nonce ? `script-src 'nonce-${nonce}'` : "script-src 'none'",
      nonce ? `style-src 'nonce-${nonce}'` : "style-src 'none'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "font-src 'self'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join('; '),
  );
  h.set('strict-transport-security', 'max-age=63072000; includeSubDomains; preload');
  h.set('x-frame-options', 'DENY');
  h.set('x-content-type-options', 'nosniff');
  h.set('referrer-policy', 'no-referrer');
  h.set('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  h.set('cross-origin-opener-policy', 'same-origin');
  h.set('cross-origin-resource-policy', 'same-origin');
  if (!h.has('cache-control')) h.set('cache-control', 'no-store');
}

app.use('*', async (c, next) => {
  await next();
  const nonce = c.get('cspNonce' as never) as string | undefined;
  // Responses from Durable Objects / streams may have immutable headers: rebuild if needed.
  try {
    securityHeaders(c.res.headers, nonce);
  } catch {
    const r = new Response(c.res.body, c.res);
    securityHeaders(r.headers, nonce);
    c.res = r;
  }
});

app.get('/', (c) => {
  const nonce = randomToken(16);
  c.set('cspNonce' as never, nonce as never);
  return c.html(renderDashboard(nonce));
});
app.get('/assets/vazirmatn.woff2', () =>
  new Response(vazirmatn(), { headers: { 'content-type': 'font/woff2', 'cache-control': 'public, max-age=31536000, immutable' } }),
);
app.get('/favicon.ico', () => new Response(null, { status: 204 }));
app.get('/healthz', (c) => c.json({ ok: true }));

app.route('/api', api);

// ---------------------------------------------------------------- MCP (Streamable HTTP)

app.all('/mcp', async (c) => {
  const req = c.req.raw;
  const ip = clientIp(req);
  if (!['POST', 'GET', 'DELETE'].includes(req.method)) return jsonRpcError(405, -32000, 'Method not allowed');
  const issues = configIssues(c.env);
  if (issues.length) return jsonRpcError(503, -32000, `Server is not configured: ${describeIssues(issues)}`);
  const tok = await verifyMcpBearer(c.env, req);
  if (!tok) {
    const rl = await rateLimit(c.env, `mcpauth:${ip}`, 20, 60);
    await audit(c.env, { actor: 'anonymous', action: 'mcp.auth', outcome: rl.ok ? 'denied' : 'rate_limited', ip });
    const r = jsonRpcError(rl.ok ? 401 : 429, -32001, rl.ok ? 'Unauthorized: missing or invalid bearer token' : 'Too many failed attempts');
    r.headers.set('www-authenticate', 'Bearer realm="my-ssh-mcp"');
    return r;
  }
  const rl = await rateLimit(c.env, `mcp:${tok.id}`, 300, 60);
  if (!rl.ok) return jsonRpcError(429, -32000, 'Rate limit exceeded');
  const len = Number(req.headers.get('content-length') ?? '0');
  if (len > 10 * 1024 * 1024) return jsonRpcError(413, -32600, 'Request too large');

  let sessionId = req.headers.get('mcp-session-id');
  let isNew = false;
  if (!sessionId) {
    if (req.method !== 'POST') return jsonRpcError(400, -32000, 'Bad Request: Mcp-Session-Id header is required');
    sessionId = crypto.randomUUID();
    isNew = true;
  } else if (!/^[0-9a-f-]{36}$/i.test(sessionId)) {
    return jsonRpcError(404, -32001, 'Session not found');
  }
  const stub = c.env.MCP_SESSION.get(c.env.MCP_SESSION.idFromName(sessionId));
  const headers = new Headers(req.headers);
  headers.set('x-mcp-internal-session', sessionId);
  headers.set('x-mcp-internal-token-id', tok.id);
  headers.set('x-mcp-internal-token-name', tok.name);
  if (isNew) headers.set('x-mcp-internal-new', '1');
  else headers.delete('x-mcp-internal-new');
  const fwd = new Request(req.url, { method: req.method, headers, body: req.body, duplex: 'half' } as RequestInit);
  return stub.fetch(fwd);
});

app.notFound((c) => c.json({ error: 'not found' }, 404));

export default app;
