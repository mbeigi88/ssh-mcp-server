import { describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import { api, createMcpToken, login, mcpCall, mcpInit } from '../helpers';

let n = 0;
async function mkServer(auth: Awaited<ReturnType<typeof login>>, extra: Record<string, unknown> = {}) {
  const r = await api(auth, 'POST', '/servers', { name: `aa-${++n}-${Date.now()}`, host: 'example.com', username: 'deploy', auth_method: 'password', password: 'x', ...extra });
  return r;
}

describe('auto-approve migration', () => {
  it('adds servers.auto_approve (default off, constrained) and audit_log flags', async () => {
    const cols = (await env.DB.prepare('PRAGMA table_info(servers)').all<{ name: string; dflt_value: string; notnull: number }>()).results;
    const c = cols.find((x) => x.name === 'auto_approve')!;
    expect(c).toBeTruthy();
    expect(c.dflt_value).toBe("'off'");
    expect(c.notnull).toBe(1);
    const acols = (await env.DB.prepare('PRAGMA table_info(audit_log)').all<{ name: string }>()).results.map((x) => x.name);
    expect(acols).toEqual(expect.arrayContaining(['auto_approved', 'auto_level']));
    // a row inserted the old way (no auto_approve column) gets 'off'; invalid values are rejected
    const now = Date.now();
    await env.DB.prepare("INSERT INTO servers (id, name, host, port, username, auth_method, created_at, updated_at) VALUES ('srv_legacy', 'legacy', 'example.com', 22, 'u', 'password', ?, ?)").bind(now, now).run();
    expect((await env.DB.prepare("SELECT auto_approve FROM servers WHERE id = 'srv_legacy'").first<{ auto_approve: string }>())!.auto_approve).toBe('off');
    await expect(env.DB.prepare("UPDATE servers SET auto_approve = 'yolo' WHERE id = 'srv_legacy'").run()).rejects.toThrow(/CHECK/i);
    await env.DB.prepare("DELETE FROM servers WHERE id = 'srv_legacy'").run();
  });
});

describe('auto-approve setting API', () => {
  it('new servers default to off; the global default applies to new servers only', async () => {
    const auth = await login();
    const a = await mkServer(auth);
    expect(a.status).toBe(201);
    expect(a.json.auto_approve).toBe('off');
    expect((await api(auth, 'GET', '/settings')).json.default_auto_approve).toBe('off');
    expect((await api(auth, 'PATCH', '/settings', { default_auto_approve: 'safe' })).status).toBe(200);
    const b = await mkServer(auth);
    expect(b.json.auto_approve).toBe('safe');
    expect((await api(auth, 'GET', `/servers/${a.json.id}`)).json.auto_approve).toBe('off'); // existing unchanged
    // "all" as a global default needs the typed confirmation
    const bad = await api(auth, 'PATCH', '/settings', { default_auto_approve: 'all' });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toMatch(/confirmation word/);
    expect((await api(auth, 'PATCH', '/settings', { default_auto_approve: 'all', default_auto_approve_confirm: 'تأیید' })).json.default_auto_approve).toBe('all');
    expect((await api(auth, 'PATCH', '/settings', { default_auto_approve: 'off' })).status).toBe(200);
  });

  it('explicit level on create/PATCH; "all" requires the typed confirmation', async () => {
    const auth = await login();
    expect((await mkServer(auth, { auto_approve: 'all' })).status).toBe(400);
    const s = await mkServer(auth, { auto_approve: 'all', auto_approve_confirm: 'CONFIRM' });
    expect(s.status).toBe(201);
    expect(s.json.auto_approve).toBe('all');
    const p1 = await api(auth, 'PATCH', `/servers/${s.json.id}`, { auto_approve: 'safe' });
    expect(p1.json.auto_approve).toBe('safe');
    expect((await api(auth, 'PATCH', `/servers/${s.json.id}`, { auto_approve: 'all' })).status).toBe(400);
    expect((await api(auth, 'PATCH', `/servers/${s.json.id}`, { auto_approve: 'all', auto_approve_confirm: 'confirm' })).json.auto_approve).toBe('all');
    expect((await api(auth, 'PATCH', `/servers/${s.json.id}`, { auto_approve: 'nope' })).status).toBe(400);
  });

  it('quick switch endpoint: CSRF, validation, typed confirm for all, audited', async () => {
    const auth = await login();
    const s = (await mkServer(auth)).json;
    const noCsrf = await api({ cookie: auth.cookie, csrf: 'wrong' }, 'POST', `/servers/${s.id}/auto-approve`, { level: 'safe' });
    expect(noCsrf.status).toBe(403);
    expect((await api(null, 'POST', `/servers/${s.id}/auto-approve`, { level: 'safe' })).status).toBe(401);
    expect((await api(auth, 'POST', `/servers/${s.id}/auto-approve`, { level: 'bogus' })).status).toBe(400);
    expect((await api(auth, 'POST', `/servers/${s.id}/auto-approve`, { level: 'safe' })).json.auto_approve).toBe('safe');
    expect((await api(auth, 'POST', `/servers/${s.id}/auto-approve`, { level: 'all' })).status).toBe(400);
    expect((await api(auth, 'POST', `/servers/${s.id}/auto-approve`, { level: 'all', confirm_text: 'yes' })).status).toBe(400);
    expect((await api(auth, 'POST', `/servers/${s.id}/auto-approve`, { level: 'all', confirm_text: 'تایید' })).json.auto_approve).toBe('all');
    expect((await api(auth, 'POST', `/servers/${s.id}/auto-approve`, { level: 'off' })).json.auto_approve).toBe('off');
    const audit = (await api(auth, 'GET', '/audit?limit=50')).json as Array<{ action: string; server_id: string; outcome: string }>;
    const mine = audit.filter((a) => a.action === 'server.auto_approve' && a.server_id === s.id).map((a) => a.outcome);
    expect(mine).toEqual(['off', 'all', 'safe']);
    expect((await api(auth, 'POST', '/servers/srv_missing/auto-approve', { level: 'safe' })).status).toBe(404);
  });
});

describe('auto-approve with MCP (no SSH reached)', () => {
  it('catastrophic commands still need approval at "safe"; read-only blocks even at "all"', async () => {
    const auth = await login();
    const s = (await mkServer(auth, { auto_approve: 'safe' })).json;
    const { token } = await createMcpToken(auth);
    const sid = await mcpInit(token);
    const r = await mcpCall(token, sid, 'execute_command', { server: s.name, command: 'mkfs.ext4 /dev/sdb1' });
    expect(r.data.status).toBe('confirmation_required');
    expect(r.data.catastrophic.join(' ')).toMatch(/mkfs/);
    expect(r.data.message).toMatch(/catastrophic/);
    const d = await mcpCall(token, sid, 'delete_file', { server: s.name, path: '/etc/ssh/sshd_config' });
    expect(d.data.status).toBe('confirmation_required');
    const list = await mcpCall(token, sid, 'list_servers');
    expect(list.data.find((x: { id: string }) => x.id === s.id).auto_approve).toBe('safe');
    // read-only overrides everything
    await api(auth, 'POST', `/servers/${s.id}/auto-approve`, { level: 'all', confirm_text: 'CONFIRM' });
    await api(auth, 'PATCH', `/servers/${s.id}`, { policy_mode: 'read_only' });
    const b = await mcpCall(token, sid, 'execute_command', { server: s.name, command: 'rm -rf /tmp/x' });
    expect(b.data.status).toBe('blocked');
    const bd = await mcpCall(token, sid, 'delete_file', { server: s.name, path: '/tmp/x' });
    expect(bd.data.status).toBe('blocked');
  });

  it('approve-all approves every pending item (or one server only)', async () => {
    const auth = await login();
    const s1 = (await mkServer(auth)).json;
    const s2 = (await mkServer(auth)).json;
    const { token } = await createMcpToken(auth);
    const sid = await mcpInit(token);
    const ids: Record<string, string[]> = { [s1.id]: [], [s2.id]: [] };
    for (const [srv, cmd] of [[s1, 'rm -rf /srv/a'], [s1, 'rm -rf /srv/b'], [s2, 'rm -rf /srv/c']] as const) {
      const r = await mcpCall(token, sid, 'execute_command', { server: srv.name, command: cmd });
      expect(r.data.status).toBe('confirmation_required');
      ids[srv.id].push(r.data.confirmation_id);
    }
    const one = await api(auth, 'POST', '/confirmations/approve-all', { server_id: s2.id });
    expect(one.json.approved).toBe(1);
    expect(one.json.ids).toEqual(ids[s2.id]);
    const st = async (id: string) => (await env.DB.prepare('SELECT status FROM pending_confirmations WHERE id = ?').bind(id).first<{ status: string }>())!.status;
    expect(await st(ids[s1.id][0])).toBe('pending');
    expect((await api({ cookie: auth.cookie, csrf: 'x' }, 'POST', '/confirmations/approve-all', {})).status).toBe(403);
    expect((await api(auth, 'POST', '/confirmations/approve-all', { bogus: 1 })).status).toBe(400);
    const all = await api(auth, 'POST', '/confirmations/approve-all', {});
    expect(all.json.approved).toBeGreaterThanOrEqual(2);
    for (const id of ids[s1.id]) expect(await st(id)).toBe('approved');
    expect((await api(auth, 'POST', '/confirmations/approve-all', {})).json.approved).toBe(0);
    const audit = (await api(auth, 'GET', '/audit?limit=20')).json as Array<{ action: string }>;
    expect(audit.filter((a) => a.action === 'confirmation.approve_all').length).toBeGreaterThanOrEqual(3);
  });

  it('overview and audit expose the auto_approved flag', async () => {
    const auth = await login();
    const s = (await mkServer(auth)).json;
    // simulate an auto-approved execution row the way ops.ts writes it
    const { audit } = await import('../../src/lib/db');
    await audit(env as never, { actor: 'mcp:test', action: 'command.exec', server_id: s.id, auto_level: 'safe', detail: { command: 'rm -rf /tmp/x', auto_approved: true } });
    await audit(env as never, { actor: 'mcp:test', action: 'command.exec', server_id: s.id, auto_level: 'off', detail: { command: 'ls' } });
    const ov = await api(auth, 'GET', '/overview');
    const rows = ov.json.recent_activity.filter((a: { server_id: string }) => a.server_id === s.id);
    expect(rows[0]).toMatchObject({ auto_approved: 0, auto_level: null });
    expect(rows[1]).toMatchObject({ auto_approved: 1, auto_level: 'safe' });
    const au = (await api(auth, 'GET', '/audit?limit=5')).json;
    expect(au.some((a: { auto_approved: number; auto_level: string }) => a.auto_approved === 1 && a.auto_level === 'safe')).toBe(true);
  });
});
