// One Durable Object per MCP session (Mcp-Session-Id). Hosts an official SDK McpServer
// bound to a WebStandardStreamableHTTPServerTransport. The session is pinned to the MCP
// token that created it. If the DO was evicted, the session is restored from storage
// (initialized flag + token binding) so clients do not need to re-initialize.
import { DurableObject } from 'cloudflare:workers';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import type { Env } from '../env';
import { registerTools } from '../mcp/tools';

export const SERVER_INFO = { name: 'my-ssh-mcp', version: '1.0.0' };

interface Meta { sessionId: string; tokenId: string; tokenName: string; initialized: boolean; createdAt: number }

export class McpSession extends DurableObject<Env> {
  private transport: WebStandardStreamableHTTPServerTransport | null = null;
  private server: McpServer | null = null;
  private meta: Meta | null = null;

  private build(meta: Meta, restore: boolean) {
    const server = new McpServer(SERVER_INFO, {
      capabilities: { tools: {} },
      instructions:
        'SSH management server. Use list_servers first. Destructive operations return confirmation_required; ask the human to approve in the dashboard, then retry with confirmation_id. Never guess confirm tokens.',
    });
    registerTools(server, this.env, `mcp:${meta.tokenName}`);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => meta.sessionId,
      enableJsonResponse: true,
      onsessioninitialized: async () => {
        meta.initialized = true;
        await this.ctx.storage.put('meta', meta);
      },
      onsessionclosed: async () => {
        await this.ctx.storage.deleteAll();
        this.meta = null;
      },
    });
    if (restore) {
      // Session resurrection after eviction: mark the transport as already initialized.
      const t = transport as unknown as { _initialized: boolean; sessionId: string };
      t._initialized = true;
      t.sessionId = meta.sessionId;
    }
    this.server = server;
    this.transport = transport;
    this.meta = meta;
    return server.connect(transport);
  }

  async fetch(req: Request): Promise<Response> {
    const sessionId = req.headers.get('x-mcp-internal-session')!;
    const tokenId = req.headers.get('x-mcp-internal-token-id')!;
    const tokenName = req.headers.get('x-mcp-internal-token-name') ?? 'token';
    const isNew = req.headers.get('x-mcp-internal-new') === '1';

    if (!this.transport) {
      const stored = await this.ctx.storage.get<Meta>('meta');
      if (stored?.initialized) {
        await this.build(stored, true);
      } else if (isNew) {
        await this.build({ sessionId, tokenId, tokenName, initialized: false, createdAt: Date.now() }, false);
      } else {
        return jsonRpcError(404, -32001, 'Session not found');
      }
    }
    if (this.meta && this.meta.tokenId !== tokenId) {
      return jsonRpcError(403, -32003, 'Session belongs to a different token');
    }
    // strip internal headers before handing to the SDK
    const headers = new Headers(req.headers);
    for (const h of ['x-mcp-internal-session', 'x-mcp-internal-token-id', 'x-mcp-internal-token-name', 'x-mcp-internal-new']) headers.delete(h);
    const clean = new Request(req.url, { method: req.method, headers, body: req.body, duplex: 'half' } as RequestInit);
    return this.transport!.handleRequest(clean);
  }

  /** Test hook: simulate eviction by dropping in-memory state. */
  async dropMemoryForTests(): Promise<void> {
    this.transport = null;
    this.server = null;
    this.meta = null;
  }
}

export function jsonRpcError(status: number, code: number, message: string): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }), { status, headers: { 'content-type': 'application/json' } });
}
