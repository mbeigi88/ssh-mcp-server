// Integration tests: the real Worker (in workerd) talks to a REAL OpenSSH server
// (test/sshd/start.sh, 127.0.0.1:2222). DEV_ALLOW_PRIVATE_TARGETS is enabled only here.
import { beforeAll, describe, expect, it } from 'vitest';
import { SELF, env, runInDurableObject, runDurableObjectAlarm } from 'cloudflare:test';
import { api, BASE, createMcpToken, login, mcpCall, mcpInit, type Auth } from '../helpers';
import type { SshSession } from '../../src/do/ssh-session';

const KEYS = JSON.parse(env.TEST_KEYS!) as Record<string, string>;
const PORT = Number(env.SSH_TEST_PORT ?? 2222);
const USER = 'sshtest';
const PASSWORD = 'T3stPassw0rd!';

async function fpOfPub(pub: string): Promise<string> {
  const blob = Uint8Array.from(atob(pub.trim().split(/\s+/)[1]), (c) => c.charCodeAt(0));
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', blob));
  return 'SHA256:' + btoa(String.fromCharCode(...d)).replace(/=+$/, '');
}

let auth: Auth;
let hostFp: string;
let n = 0;

async function addServer(extra: Record<string, unknown>) {
  const r = await api(auth, 'POST', '/servers', { name: `srv${++n}-${Date.now()}`, host: '127.0.0.1', port: PORT, username: USER, ...extra });
  if (r.status !== 201) throw new Error('create failed: ' + JSON.stringify(r.json));
  return r.json as { id: string; name: string };
}
/** Adds a server and completes TOFU by approving the captured fingerprint. */
async function addTrusted(extra: Record<string, unknown>) {
  const s = await addServer(extra);
  const c = await api(auth, 'POST', `/servers/${s.id}/connect`);
  expect(c.json.code).toBe('HOSTKEY_UNKNOWN');
  expect((await api(auth, 'POST', `/servers/${s.id}/approve-hostkey`, { fingerprint: c.json.fingerprint })).status).toBe(200);
  return s;
}
async function execNdjson(serverId: string, command: string, extra: Record<string, unknown> = {}) {
  const r = await SELF.fetch(`${BASE}/api/servers/${serverId}/exec`, {
    method: 'POST', headers: { cookie: auth.cookie, 'x-csrf-token': auth.csrf, 'content-type': 'application/json' }, body: JSON.stringify({ command, ...extra }),
  });
  if (r.status !== 200) return { status: r.status, json: (await r.json()) as any, events: [] as any[] };
  const text = await r.text();
  return { status: 200, execId: r.headers.get('x-exec-id'), events: text.trim().split('\n').map((l) => JSON.parse(l)) };
}

beforeAll(async () => {
  auth = await login();
  hostFp = await fpOfPub(KEYS['host_ed25519.pub']);
});

describe('host key verification (TOFU)', () => {
  it('captures the fingerprint on first contact, refuses to connect until approved, then connects', async () => {
    const s = await addServer({ auth_method: 'password', password: PASSWORD });
    const c = await api(auth, 'POST', `/servers/${s.id}/connect`);
    expect(c.status).toBe(502);
    expect(c.json.code).toBe('HOSTKEY_UNKNOWN');
    expect(c.json.fingerprint).toBe(hostFp); // matches ssh-keygen -lf of the real host key
    expect(c.json.algo).toBe('ssh-ed25519');
    const pub = (await api(auth, 'GET', `/servers/${s.id}`)).json;
    expect(pub.status).toBe('hostkey_pending');
    expect(pub.pending_fingerprint).toBe(hostFp);
    // approving a different fingerprint is refused
    expect((await api(auth, 'POST', `/servers/${s.id}/approve-hostkey`, { fingerprint: 'SHA256:' + 'A'.repeat(43) })).status).toBe(409);
    expect((await api(auth, 'POST', `/servers/${s.id}/approve-hostkey`, { fingerprint: hostFp })).status).toBe(200);
    const t = await api(auth, 'POST', `/servers/${s.id}/test`);
    expect(t.status).toBe(200);
    expect(t.json.ok).toBe(true);
    expect(t.json.fingerprint).toBe(hostFp);
  });

  it('hard-fails on host key mismatch', async () => {
    const s = await addServer({ auth_method: 'password', password: PASSWORD, host_key_fingerprint: 'SHA256:' + 'B'.repeat(43) });
    const c = await api(auth, 'POST', `/servers/${s.id}/connect`);
    expect(c.status).toBe(502);
    expect(c.json.code).toBe('HOSTKEY_MISMATCH');
    expect(c.json.message).toMatch(/HOST KEY MISMATCH/);
    expect((await api(auth, 'GET', `/servers/${s.id}`)).json.status).toBe('hostkey_mismatch');
    const audit = await api(auth, 'GET', '/audit?limit=50');
    expect(audit.json.some((a: { action: string; server_id: string }) => a.action === 'hostkey.mismatch' && a.server_id === s.id)).toBe(true);
  });

  it('accepts a pre-pinned correct fingerprint without TOFU', async () => {
    const s = await addServer({ auth_method: 'password', password: PASSWORD, host_key_fingerprint: hostFp });
    expect((await api(auth, 'POST', `/servers/${s.id}/connect`)).json.ok).toBe(true);
  });
});

describe('authentication methods against real sshd', () => {
  it('password auth', async () => {
    const s = await addTrusted({ auth_method: 'password', password: PASSWORD });
    expect((await api(auth, 'POST', `/servers/${s.id}/test`)).json.ok).toBe(true);
  });
  it('ed25519 key auth', async () => {
    const s = await addTrusted({ auth_method: 'key', private_key: KEYS.id_ed25519 });
    expect((await api(auth, 'POST', `/servers/${s.id}/test`)).json.ok).toBe(true);
  });
  it('RSA key auth (rsa-sha2)', async () => {
    const s = await addTrusted({ auth_method: 'key', private_key: KEYS.id_rsa });
    expect((await api(auth, 'POST', `/servers/${s.id}/test`)).json.ok).toBe(true);
  });
  it('ECDSA key auth', async () => {
    const s = await addTrusted({ auth_method: 'key', private_key: KEYS.id_ecdsa });
    expect((await api(auth, 'POST', `/servers/${s.id}/test`)).json.ok).toBe(true);
  });
  it('passphrase-encrypted OpenSSH key (bcrypt-pbkdf)', async () => {
    const s = await addTrusted({ auth_method: 'key', private_key: KEYS.id_ed25519_enc, passphrase: 'k3yPass' });
    expect((await api(auth, 'POST', `/servers/${s.id}/test`)).json.ok).toBe(true);
  });
  it('rejects an encrypted key with a wrong or missing passphrase at save time', async () => {
    const bad = await api(auth, 'POST', '/servers', { name: 'badpass', host: '127.0.0.1', port: PORT, username: USER, auth_method: 'key', private_key: KEYS.id_ed25519_enc, passphrase: 'wrong' });
    expect(bad.status).toBe(400);
    expect(bad.json.error).toMatch(/passphrase|decrypt/i);
    const none = await api(auth, 'POST', '/servers', { name: 'nopass', host: '127.0.0.1', port: PORT, username: USER, auth_method: 'key', private_key: KEYS.id_ed25519_enc });
    expect(none.status).toBe(400);
  });
  it('wrong password -> AUTH_FAILED', async () => {
    const s = await addTrusted({ auth_method: 'password', password: 'definitely-wrong' }).catch(() => null);
    // TOFU step itself works without valid auth? host key check happens before auth, so approve works
    expect(s).not.toBeNull();
    const c = await api(auth, 'POST', `/servers/${s!.id}/connect`);
    expect(c.status).toBe(502);
    expect(c.json.code).toBe('AUTH_FAILED');
    const pub = (await api(auth, 'GET', `/servers/${s!.id}`)).json;
    expect(pub.status).toBe('error');
    expect(JSON.stringify(pub)).not.toContain('definitely-wrong');
  });
});

describe('network failures', () => {
  it('unreachable port -> CONNECT_FAILED quickly', async () => {
    const s = await api(auth, 'POST', '/servers', { name: 'closed-port', host: '127.0.0.1', port: 2299, username: USER, auth_method: 'password', password: 'x' });
    const t0 = Date.now();
    const c = await api(auth, 'POST', `/servers/${s.json.id}/connect`);
    expect(c.status).toBe(502);
    expect(['CONNECT_FAILED', 'DISCONNECTED']).toContain(c.json.code);
    expect(Date.now() - t0).toBeLessThan(10000);
    const hist = await api(auth, 'GET', `/servers/${s.json.id}/history`);
    expect(hist.json.length).toBeGreaterThan(0);
  });
  it('blackholed address -> TIMEOUT', async () => {
    const s = await api(auth, 'POST', '/servers', { name: 'blackhole', host: '10.255.255.1', port: 22, username: USER, auth_method: 'password', password: 'x' });
    const c = await api(auth, 'POST', `/servers/${s.json.id}/connect`);
    expect(c.status).toBe(502);
    expect(c.json.code).toBe('TIMEOUT');
  }, 60000);
});

describe('exec via dashboard API (streaming NDJSON)', () => {
  let sid: string;
  beforeAll(async () => { sid = (await addTrusted({ auth_method: 'password', password: PASSWORD })).id; });

  it('streams stdout and stderr separately with exit code', async () => {
    const r = await execNdjson(sid, 'echo out1; echo err1 >&2; echo out2; exit 7');
    expect(r.status).toBe(200);
    const out = r.events.filter((e) => e.type === 'stdout').map((e) => e.data).join('');
    const err = r.events.filter((e) => e.type === 'stderr').map((e) => e.data).join('');
    expect(out).toBe('out1\nout2\n');
    expect(err).toBe('err1\n');
    const exit = r.events.find((e) => e.type === 'exit');
    expect(exit.exitCode).toBe(7);
    expect(exit.status).toBe('completed');
    const stored = await api(auth, 'GET', `/commands/${r.execId}`);
    expect(stored.json.stdout).toBe('out1\nout2\n');
    expect(stored.json.exit_code).toBe(7);
  });

  it('caps output (bounded memory) and reports truncation', async () => {
    await api(auth, 'PATCH', '/settings', { max_output_bytes: 4096 });
    const r = await execNdjson(sid, 'head -c 200000 /dev/zero | tr "\\0" "x"');
    const out = r.events.filter((e) => e.type === 'stdout').map((e) => e.data).join('');
    expect(out.length).toBe(4096);
    expect(r.events.some((e) => e.type === 'truncated')).toBe(true);
    expect(r.events.find((e) => e.type === 'exit').stdoutTruncated).toBe(true);
    await api(auth, 'PATCH', '/settings', { max_output_bytes: 262144 });
  });

  it('enforces command timeout', async () => {
    const r = await execNdjson(sid, 'sleep 30', { timeout_seconds: 2 });
    const exit = r.events.find((e) => e.type === 'exit');
    expect(exit.status).toBe('timeout');
  });

  it('cancels a running command and the remote process is killed', async () => {
    const p = execNdjson(sid, 'sleep 301');
    await new Promise((r) => setTimeout(r, 1500));
    const running = await api(auth, 'GET', `/servers/${sid}/status`);
    expect(running.json.running.length).toBe(1);
    const cancel = await api(auth, 'POST', `/servers/${sid}/exec/${running.json.running[0]}/cancel`);
    expect(cancel.json.ok).toBe(true);
    const r = await p;
    expect(r.events.find((e) => e.type === 'exit').status).toBe('cancelled');
    await new Promise((res) => setTimeout(res, 1000));
    const check = await execNdjson(sid, "ps -eo args | grep -c '^sleep 301$' || true");
    const count = check.events.filter((e) => e.type === 'stdout').map((e) => e.data).join('').trim();
    expect(count).toBe('0');
  });

  it('asks for confirmation before destructive commands in the terminal', async () => {
    const r = await execNdjson(sid, 'rm -rf /tmp/cfsshmcp-nonexistent-dir');
    expect(r.status).toBe(409);
    expect(r.json.status).toBe('confirmation_required');
    const ok = await execNdjson(sid, 'rm -rf /tmp/cfsshmcp-nonexistent-dir', { confirmed: true });
    expect(ok.events.find((e) => e.type === 'exit').exitCode).toBe(0);
  });

  it('disconnects after the idle timeout (alarm)', async () => {
    const stub = env.SSH_SESSION.get(env.SSH_SESSION.idFromName(sid));
    await api(auth, 'POST', `/servers/${sid}/connect`);
    expect((await stub.status()).connected).toBe(true);
    await runInDurableObject(stub, (inst: SshSession) => { (inst as unknown as { lastActivity: number }).lastActivity = Date.now() - 3600_000; });
    await runDurableObjectAlarm(stub);
    expect((await stub.status()).connected).toBe(false);
  });
});

describe('MCP tools against real sshd', () => {
  let token: string;
  let sid: string;
  let server: { id: string; name: string };
  const dir = `/tmp/cfsshmcp-${Date.now()}`;

  beforeAll(async () => {
    server = await addTrusted({ auth_method: 'key', private_key: KEYS.id_ed25519 });
    token = (await createMcpToken(auth, 'integration')).token;
    sid = await mcpInit(token);
  });

  it('test_ssh_connection / get_server_status / get_server_info', async () => {
    expect((await mcpCall(token, sid, 'test_ssh_connection', { server: server.name })).data.ok).toBe(true);
    const st = await mcpCall(token, sid, 'get_server_status', { server: server.id });
    expect(st.data.connected).toBe(true);
    const info = await mcpCall(token, sid, 'get_server_info', { server: server.name });
    expect(info.data.user).toBe('sshtest');
    expect(info.data.kernel).toMatch(/Linux/);
  });

  it('execute_command returns stdout/stderr/exit code and a retrievable result', async () => {
    const r = await mcpCall(token, sid, 'execute_command', { server: server.name, command: 'echo hello; echo oops >&2; exit 3' });
    expect(r.data).toMatchObject({ status: 'completed', exit_code: 3, stdout: 'hello\n', stderr: 'oops\n', classification: 'read' });
    const g = await mcpCall(token, sid, 'get_command_result', { result_id: r.data.result_id });
    expect(g.data.stdout).toBe('hello\n');
    const to = await mcpCall(token, sid, 'execute_command', { server: server.name, command: 'sleep 20', timeout_seconds: 1 });
    expect(to.data.status).toBe('timeout');
  });

  it('execute_commands runs sequentially and stops on error', async () => {
    const r = await mcpCall(token, sid, 'execute_commands', { server: server.name, commands: ['echo a', 'false', 'echo never'] });
    expect(r.data.executed).toBe(2);
    expect(r.data.results[1].exit_code).toBe(1);
  });

  it('argument injection is neutralised by quoting', async () => {
    const r = await mcpCall(token, sid, 'get_service_status', { server: server.name, service: 'ssh; touch /tmp/pwned' });
    expect(r.isError).toBe(true);
    const r2 = await mcpCall(token, sid, 'docker_logs', { server: server.name, container: '$(id)' });
    expect(r2.isError).toBe(true);
  });

  it('SFTP: mkdir, write, read (paginated), upload chunks, download, list, rename, delete with confirmation', async () => {
    expect((await mcpCall(token, sid, 'create_directory', { server: server.name, path: dir })).isError).toBe(false);
    const w = await mcpCall(token, sid, 'write_file', { server: server.name, path: `${dir}/a.txt`, content: 'hello world\nسلام\n' });
    expect(w.data.bytes_written).toBe(new TextEncoder().encode('hello world\nسلام\n').length);
    const rd = await mcpCall(token, sid, 'read_file', { server: server.name, path: `${dir}/a.txt` });
    expect(rd.data.content).toBe('hello world\nسلام\n');
    expect(rd.data.eof).toBe(true);
    const page = await mcpCall(token, sid, 'read_file', { server: server.name, path: `${dir}/a.txt`, offset: 6, length: 5 });
    expect(page.data.content).toBe('world');
    expect(page.data.next_offset).toBe(11);

    // upload a 300 KiB binary in two chunks and verify with sha256sum on the server
    const bin = new Uint8Array(300 * 1024).map((_, i) => (i * 31 + 7) & 255);
    const b64 = (u: Uint8Array) => { let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };
    const u1 = await mcpCall(token, sid, 'upload_file', { server: server.name, path: `${dir}/blob.bin`, content_base64: b64(bin.subarray(0, 200000)), offset: 0 });
    expect(u1.data.next_offset).toBe(200000);
    await mcpCall(token, sid, 'upload_file', { server: server.name, path: `${dir}/blob.bin`, content_base64: b64(bin.subarray(200000)), offset: 200000 });
    const localHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bin)), (b) => b.toString(16).padStart(2, '0')).join('');
    const remote = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `sha256sum ${dir}/blob.bin` });
    expect(remote.data.stdout.split(' ')[0]).toBe(localHash);

    const d1 = await mcpCall(token, sid, 'download_file', { server: server.name, path: `${dir}/blob.bin`, length: 100000 });
    expect(d1.data.bytes).toBe(100000);
    expect(d1.data.eof).toBe(false);
    expect(d1.data.content_base64).toBe(b64(bin.subarray(0, 100000)));

    const ls = await mcpCall(token, sid, 'list_directory', { server: server.name, path: dir });
    expect(ls.data.entries.map((e: { name: string }) => e.name).sort()).toEqual(['a.txt', 'blob.bin']);
    expect(ls.data.entries.find((e: { name: string }) => e.name === 'blob.bin').size).toBe(300 * 1024);

    expect((await mcpCall(token, sid, 'rename_file', { server: server.name, from: `${dir}/a.txt`, to: `${dir}/b.txt` })).isError).toBe(false);

    const del = await mcpCall(token, sid, 'delete_file', { server: server.name, path: `${dir}/b.txt` });
    expect(del.data.status).toBe('confirmation_required');
    expect((await api(auth, 'POST', `/confirmations/${del.data.confirmation_id}/approve`)).status).toBe(200);
    const done = await mcpCall(token, sid, 'delete_file', { server: server.name, path: 'ignored', confirmation_id: del.data.confirmation_id });
    expect(done.data).toMatchObject({ status: 'deleted', deleted: `${dir}/b.txt` });
    const reuse = await mcpCall(token, sid, 'delete_file', { server: server.name, path: 'x', confirmation_id: del.data.confirmation_id });
    expect(reuse.text).toMatch(/executed|already used/);

    // recursive delete with a one-time token the human copied from the dashboard
    const rec = await mcpCall(token, sid, 'delete_file', { server: server.name, path: dir, recursive: true });
    const tok = await api(auth, 'POST', `/confirmations/${rec.data.confirmation_id}/token`);
    const recDone = await mcpCall(token, sid, 'delete_file', { server: server.name, path: dir, confirmation_id: rec.data.confirmation_id, confirm_token: tok.json.token });
    expect(recDone.data.status).toBe('deleted');
    const gone = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `test -e ${dir} && echo exists || echo gone` });
    expect(gone.data.stdout.trim()).toBe('gone');
  });

  it('destructive command executes once after dashboard approval', async () => {
    const target = `/tmp/cfsshmcp-destroy-${Date.now()}`;
    await mcpCall(token, sid, 'execute_command', { server: server.name, command: `mkdir -p ${target}/sub && touch ${target}/sub/f` });
    const r = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `rm -rf ${target}` });
    expect(r.data.status).toBe('confirmation_required');
    await api(auth, 'POST', `/confirmations/${r.data.confirmation_id}/approve`);
    const ex = await mcpCall(token, sid, 'execute_command', { server: server.name, command: 'echo ignored-the-stored-op-runs', confirmation_id: r.data.confirmation_id });
    expect(ex.data.status).toBe('completed');
    expect(ex.data.exit_code).toBe(0);
    const chk = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `test -e ${target} && echo exists || echo gone` });
    expect(chk.data.stdout.trim()).toBe('gone');
  });

  it('system metrics tools return parsed data', async () => {
    const cpu = await mcpCall(token, sid, 'get_cpu_usage', { server: server.name });
    expect(cpu.data.cores).toBeGreaterThan(0);
    expect(typeof cpu.data.usage_percent).toBe('number');
    const mem = await mcpCall(token, sid, 'get_memory_usage', { server: server.name });
    expect(mem.data.total_bytes).toBeGreaterThan(0);
    const disk = await mcpCall(token, sid, 'get_disk_usage', { server: server.name });
    expect(Array.isArray(disk.data)).toBe(true);
    expect(disk.data.length).toBeGreaterThan(0);
    const up = await mcpCall(token, sid, 'get_system_uptime', { server: server.name });
    expect(up.data.uptime_seconds).toBeGreaterThan(0);
    const ps = await mcpCall(token, sid, 'get_running_processes', { server: server.name, limit: 5 });
    expect(ps.data.length).toBeGreaterThan(0);
    expect(ps.data.length).toBeLessThanOrEqual(5);
    const net = await mcpCall(token, sid, 'get_network_interfaces', { server: server.name });
    expect(net.data.counters.some((c: { name: string }) => c.name === 'lo')).toBe(true);
    const svc = await mcpCall(token, sid, 'get_service_status', { server: server.name, service: 'ssh' });
    expect(svc.isError).toBe(false); // test container has no systemd: properties may be empty but the call succeeds
  });

  it('docker tools report a clean error when docker is unavailable', async () => {
    const r = await mcpCall(token, sid, 'docker_ps', { server: server.name });
    // docker is not installed in the test container -> isError with the shell's message
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/docker|not found/i);
  });

  it('SFTP via dashboard API: upload chunks, streamed download, text edit, delete', async () => {
    const base = `/tmp/cfsshmcp-api-${Date.now()}`;
    expect((await api(auth, 'POST', `/servers/${server.id}/files/mkdir`, { path: base })).status).toBe(200);
    const data = new Uint8Array(150000).map((_, i) => i & 255);
    for (const [off, end] of [[0, 100000], [100000, 150000]]) {
      const r = await SELF.fetch(`${BASE}/api/servers/${server.id}/files/upload?path=${encodeURIComponent(base + '/f.bin')}&offset=${off}`, {
        method: 'POST', headers: { cookie: auth.cookie, 'x-csrf-token': auth.csrf, 'content-type': 'application/octet-stream' }, body: data.subarray(off, end),
      });
      expect(r.status).toBe(200);
    }
    const dl = await SELF.fetch(`${BASE}/api/servers/${server.id}/files/download?path=${encodeURIComponent(base + '/f.bin')}`, { headers: { cookie: auth.cookie } });
    expect(dl.status).toBe(200);
    expect(dl.headers.get('content-disposition')).toMatch(/f\.bin/);
    const got = new Uint8Array(await dl.arrayBuffer());
    expect(got.length).toBe(150000);
    expect(got.every((v, i) => v === (i & 255))).toBe(true);
    expect((await api(auth, 'POST', `/servers/${server.id}/files/write`, { path: base + '/t.txt', content: 'edit me' })).status).toBe(200);
    const st = await api(auth, 'GET', `/servers/${server.id}/files/stat?path=${encodeURIComponent(base + '/t.txt')}`);
    expect(st.json).toMatchObject({ type: 'file', size: 7 });
    const list = await api(auth, 'GET', `/servers/${server.id}/files?path=${encodeURIComponent(base)}&limit=1`);
    expect(list.json.total).toBe(2);
    expect(list.json.entries.length).toBe(1);
    expect((await api(auth, 'POST', `/servers/${server.id}/files/delete`, { path: base + '/t.txt' })).status).toBe(400); // requires explicit confirmed:true
    expect((await api(auth, 'POST', `/servers/${server.id}/files/delete`, { path: base, recursive: true, confirmed: true })).status).toBe(200);
    const missing = await api(auth, 'GET', `/servers/${server.id}/files/stat?path=${encodeURIComponent(base)}`);
    expect(missing.status).toBe(502);
    expect(missing.json.error).toMatch(/no such file/);
  });

  it('read-only policy blocks writes and modifying commands on a real server', async () => {
    await api(auth, 'PATCH', `/servers/${server.id}`, { policy_mode: 'read_only' });
    const sid2 = await mcpInit(token);
    const w = await mcpCall(token, sid2, 'write_file', { server: server.name, path: '/tmp/ro-test', content: 'x' });
    expect(w.isError).toBe(true);
    expect(w.text).toMatch(/read-only/);
    const c = await mcpCall(token, sid2, 'execute_command', { server: server.name, command: 'touch /tmp/ro-test' });
    expect(c.data.status).toBe('blocked');
    const ok = await mcpCall(token, sid2, 'execute_command', { server: server.name, command: 'whoami' });
    expect(ok.data, JSON.stringify(ok.data)).toMatchObject({ status: 'completed' });
    expect(ok.data.stdout.trim()).toBe('sshtest');
    await api(auth, 'PATCH', `/servers/${server.id}`, { policy_mode: 'modify' });
  });
});

describe('auto-approve against real sshd', () => {
  let token: string;
  let sid: string;
  let server: { id: string; name: string };
  const dir = `/tmp/cfsshmcp-aa-${Date.now()}`;
  const auditFor = async (action: string) =>
    (await env.DB.prepare('SELECT auto_approved, auto_level, detail FROM audit_log WHERE server_id = ? AND action = ? ORDER BY id DESC LIMIT 1').bind(server.id, action).first<{ auto_approved: number; auto_level: string | null; detail: string }>())!;

  beforeAll(async () => {
    server = await addTrusted({ auth_method: 'key', private_key: KEYS.id_ed25519 });
    token = (await createMcpToken(auth, 'integration-aa')).token;
    sid = await mcpInit(token);
    const mk = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `mkdir -p ${dir}/sub && echo a > ${dir}/f1 && echo b > ${dir}/sub/f2` });
    expect(mk.data.exit_code).toBe(0);
  });

  it('off (default): delete_file still requires confirmation', async () => {
    const r = await mcpCall(token, sid, 'delete_file', { server: server.name, path: `${dir}/f1` });
    expect(r.data.status).toBe('confirmation_required');
    await api(auth, 'POST', `/confirmations/${r.data.confirmation_id}/reject`);
  });

  it('safe: delete_file and rm -rf of a normal directory run immediately and are audited as auto-approved', async () => {
    expect((await api(auth, 'POST', `/servers/${server.id}/auto-approve`, { level: 'safe' })).status).toBe(200);
    const del = await mcpCall(token, sid, 'delete_file', { server: server.name, path: `${dir}/f1` });
    expect(del.data, JSON.stringify(del.data)).toMatchObject({ status: 'deleted', auto_approved: true, auto_approve_level: 'safe' });
    expect(del.data.auto_approve_note).toMatch(/AUTO-APPROVED/);
    const a = await auditFor('file.delete');
    expect(a).toMatchObject({ auto_approved: 1, auto_level: 'safe' });
    const gone = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `test -e ${dir}/f1 && echo exists || echo gone` });
    expect(gone.data.stdout.trim()).toBe('gone');

    const rm = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `rm -rf ${dir}/sub` });
    expect(rm.data).toMatchObject({ status: 'completed', exit_code: 0, classification: 'destructive', auto_approved: true, auto_approve_level: 'safe' });
    const ex = await auditFor('command.exec');
    expect(ex).toMatchObject({ auto_approved: 1, auto_level: 'safe' });
    expect(JSON.parse(ex.detail)).toMatchObject({ auto_approved: true, auto_level: 'safe' });
    const chk = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `test -e ${dir}/sub && echo exists || echo gone` });
    expect(chk.data.stdout.trim()).toBe('gone');
    expect(chk.data.auto_approved).toBeUndefined(); // read commands are never flagged
  });

  it('safe: a catastrophic command still requires confirmation and nothing runs', async () => {
    const target = `${dir}/authorized_keys`;
    const r = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `echo cfsshmcp-test >> ${target}` });
    expect(r.data.status).toBe('confirmation_required');
    expect(r.data.catastrophic.join(' ')).toMatch(/authorized_keys/);
    const chk = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `test -e ${target} && echo exists || echo absent` });
    expect(chk.data.stdout.trim()).toBe('absent');
    // dashboard terminal: same rule (409), while a non-catastrophic destructive command streams directly
    const term = await execNdjson(server.id, `echo x >> ${target}`);
    expect(term.status).toBe(409);
    expect(term.json.catastrophic.length).toBeGreaterThan(0);
    await mcpCall(token, sid, 'execute_command', { server: server.name, command: `mkdir -p ${dir}/t2` });
    const term2 = await execNdjson(server.id, `rm -rf ${dir}/t2`);
    expect(term2.status).toBe(200);
    expect(term2.events.find((e: any) => e.type === 'exit').exitCode).toBe(0);
    const ta = await auditFor('command.exec');
    expect(ta).toMatchObject({ auto_approved: 1, auto_level: 'safe' });
  });

  it('all: the catastrophic command runs without confirmation', async () => {
    expect((await api(auth, 'POST', `/servers/${server.id}/auto-approve`, { level: 'all' })).status).toBe(400);
    expect((await api(auth, 'POST', `/servers/${server.id}/auto-approve`, { level: 'all', confirm_text: 'CONFIRM' })).status).toBe(200);
    const target = `${dir}/authorized_keys`;
    const r = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `echo cfsshmcp-test >> ${target}` });
    expect(r.data, JSON.stringify(r.data)).toMatchObject({ status: 'completed', exit_code: 0, auto_approved: true, auto_approve_level: 'all' });
    expect(await auditFor('command.exec')).toMatchObject({ auto_approved: 1, auto_level: 'all' });
    const chk = await mcpCall(token, sid, 'execute_command', { server: server.name, command: `cat ${target}` });
    expect(chk.data.stdout.trim()).toBe('cfsshmcp-test');
    expect(await auditFor('command.exec')).toMatchObject({ auto_approved: 0, auto_level: null }); // the read is not flagged
  });

  it('read-only still blocks modifications even at "all"', async () => {
    await api(auth, 'PATCH', `/servers/${server.id}`, { policy_mode: 'read_only' });
    const sid2 = await mcpInit(token);
    const c = await mcpCall(token, sid2, 'execute_command', { server: server.name, command: `rm -rf ${dir}` });
    expect(c.data.status).toBe('blocked');
    const d = await mcpCall(token, sid2, 'delete_file', { server: server.name, path: `${dir}/authorized_keys` });
    expect(d.data.status).toBe('blocked');
    const still = await mcpCall(token, sid2, 'execute_command', { server: server.name, command: `test -e ${dir} && echo exists` });
    expect(still.data.stdout.trim()).toBe('exists');
    await api(auth, 'PATCH', `/servers/${server.id}`, { policy_mode: 'modify' });
    const clean = await mcpCall(token, sid2, 'execute_command', { server: server.name, command: `rm -rf ${dir}` });
    expect(clean.data.status).toBe('completed');
    await api(auth, 'POST', `/servers/${server.id}/auto-approve`, { level: 'off' });
  });
});
