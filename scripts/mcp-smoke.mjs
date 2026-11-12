#!/usr/bin/env node
// Smoke test with the OFFICIAL MCP SDK client over Streamable HTTP.
//   MCP_URL=https://.../mcp MCP_TOKEN=sshmcp_... node scripts/mcp-smoke.mjs
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
const url = new URL(process.env.MCP_URL);
const transport = new StreamableHTTPClientTransport(url, { requestInit: { headers: { Authorization: `Bearer ${process.env.MCP_TOKEN}` } } });
const client = new Client({ name: 'smoke', version: '1.0.0' });
await client.connect(transport);
console.log('server:', JSON.stringify(client.getServerVersion()), 'session:', transport.sessionId ? 'yes' : 'no');
const { tools } = await client.listTools();
console.log('tools:', tools.length, tools.map((t) => t.name).join(','));
const r = await client.callTool({ name: 'list_servers', arguments: {} });
console.log('list_servers ->', r.isError ? 'ERROR' : 'ok', r.content[0].text.slice(0, 200));
if (process.env.MCP_SERVER) {
  const e = await client.callTool({ name: 'execute_command', arguments: { server: process.env.MCP_SERVER, command: 'echo smoke-ok; uname -s' } });
  console.log('execute_command ->', e.content[0].text.slice(0, 400));
}
await transport.terminateSession();
await client.close();
