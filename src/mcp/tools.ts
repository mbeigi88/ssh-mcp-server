import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Env } from '../env';
import { getServer, getSettings, listServers, resolveServer, toPublic, UserError, type ServerRow } from '../lib/db';
import { shQuote, validateContainerRef, validateRemotePath, validateServiceName } from '../lib/quote';
import { checkFileOp, deleteFile, execOn, runCommand, sshStub, type OpOutcome } from '../services/ops';
import type { StoredExecResult } from '../do/ssh-session';
import type { AutoApproval } from '../lib/auto-approve';

export const MAX_TOOL_TEXT = 200_000;
const MAX_FILE_CHUNK = 1024 * 1024; // read_file / download_file per call
const MAX_WRITE = 5 * 1024 * 1024;

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean; structuredContent?: Record<string, unknown> };

function ok(data: unknown): ToolResult {
  let text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  if (text.length > MAX_TOOL_TEXT) text = text.slice(0, MAX_TOOL_TEXT) + `\n…[truncated: tool output exceeded ${MAX_TOOL_TEXT} characters]`;
  return { content: [{ type: 'text', text }] };
}
function fail(message: string): ToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  return Promise.race([p, new Promise<T>((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out after ${Math.round(ms / 1000)}s`)), ms); })]).finally(() => clearTimeout(t));
}

const serverArg = z.string().max(64).optional().describe('Server name or id. Defaults to the default server.');

function execView(r: StoredExecResult) {
  return {
    result_id: r.id,
    status: r.status,
    exit_code: r.exitCode,
    signal: r.signal,
    stdout: r.stdout,
    stderr: r.stderr,
    stdout_truncated: r.stdoutTruncated,
    stderr_truncated: r.stderrTruncated,
    duration_ms: r.durationMs,
    ...(r.error ? { error: r.error } : {}),
  };
}

function outcomeView(o: OpOutcome<StoredExecResult>) {
  if (o.kind === 'done') return { classification: o.classification.classification, ...execView(o.value), ...autoView(o.auto) };
  if (o.kind === 'blocked') return { status: 'blocked', classification: o.classification.classification, reason: o.reason };
  return { status: 'confirmation_required', classification: 'destructive', confirmation_id: o.confirmation_id, expires_at: new Date(o.expires_at).toISOString(), reason: o.reason, ...(o.catastrophic ? { catastrophic: o.catastrophic } : {}), message: o.message };
}

function autoView(a?: AutoApproval) {
  if (!a) return {};
  return { auto_approved: true, auto_approve_level: a.level, auto_approve_note: `Destructive operation (${a.reason}) was AUTO-APPROVED by this server's auto-approve setting (level "${a.level}") and executed without a human confirmation.` };
}

/** Runs a fixed, tool-built read-only command and returns stdout (throws on failure). */
async function readCmd(env: Env, actor: string, server: ServerRow, cmd: string, timeoutSeconds = 30): Promise<StoredExecResult> {
  const r = await execOn(env, actor, server, cmd, 'read', timeoutSeconds);
  if (r.status === 'failed') throw new UserError(r.error ?? 'command failed');
  return r;
}

export function registerTools(mcp: McpServer, env: Env, actor: string) {
  const tool = <S extends z.ZodRawShape>(
    name: string,
    description: string,
    shape: S,
    handler: (args: z.infer<z.ZodObject<S>>) => Promise<ToolResult>,
    opts: { readOnly?: boolean; destructive?: boolean; timeoutMs?: number } = {},
  ) => {
    mcp.registerTool(
      name,
      {
        description,
        inputSchema: shape,
        annotations: { readOnlyHint: !!opts.readOnly, destructiveHint: !!opts.destructive, openWorldHint: true },
      },
      (async (args: z.infer<z.ZodObject<S>>) => {
        try {
          return await withTimeout(handler(args), opts.timeoutMs ?? 120_000, name);
        } catch (e) {
          return fail((e as Error).message || String(e));
        }
      }) as never,
    );
  };

  // ---------------------------------------------------------------- servers

  tool('list_servers', 'List configured SSH servers (no credentials are ever returned).', {}, async () => {
    const rows = await listServers(env);
    return ok(rows.map((r) => {
      const p = toPublic(r);
      return { id: p.id, name: p.name, host: p.host, port: p.port, username: p.username, labels: p.labels, default: p.is_default, status: p.status, policy_mode: p.policy_mode, auto_approve: p.auto_approve, host_key_trusted: !!p.host_key_fingerprint, last_connected_at: p.last_connected_at };
    }));
  }, { readOnly: true });

  tool('get_server_status', 'Get connection status, host-key state and last error for a server.', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const live = await sshStub(env, row.id).status();
    const fresh = (await getServer(env, row.id))!;
    return ok({ id: row.id, name: row.name, connected: live.connected, connected_at: live.connectedAt, last_activity: live.lastActivity, running_commands: live.running.length, status: fresh.status, last_error: fresh.last_error, host_key_fingerprint: fresh.host_key_fingerprint, pending_fingerprint: fresh.pending_fingerprint, policy_mode: fresh.policy_mode, auto_approve: toPublic(fresh).auto_approve });
  }, { readOnly: true });

  tool('test_ssh_connection', 'Connect (verifying the host key) and run a trivial command to prove the SSH session works.', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const c = await sshStub(env, row.id).openSession(row.id);
    if (!c.ok) return fail(`[${c.code}] ${c.message}`);
    const r = await readCmd(env, actor, row, 'echo ok', 15);
    return ok({ ok: r.stdout.trim() === 'ok', fingerprint: c.fingerprint, latency_ms: r.durationMs });
  }, { readOnly: true });

  tool('get_server_info', 'OS, kernel, hostname, CPU count and architecture of the server.', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const r = await readCmd(env, actor, row, "echo \"hostname=$(hostname)\"; echo \"kernel=$(uname -sr)\"; echo \"arch=$(uname -m)\"; echo \"cpus=$(nproc 2>/dev/null)\"; . /etc/os-release 2>/dev/null; echo \"os=${PRETTY_NAME:-unknown}\"; echo \"user=$(id -un)\"");
    const info: Record<string, string> = {};
    for (const line of r.stdout.split('\n')) { const i = line.indexOf('='); if (i > 0) info[line.slice(0, i)] = line.slice(i + 1); }
    return ok(info);
  }, { readOnly: true });

  // ---------------------------------------------------------------- commands

  const execShape = {
    server: serverArg,
    command: z.string().min(1).max(16384).describe('Shell command to run (non-interactive, no TTY).'),
    timeout_seconds: z.number().int().min(1).max(600).optional().describe('Timeout (default from settings, max 600).'),
    max_output_bytes: z.number().int().min(256).max(4 * 1024 * 1024).optional().describe('Per-stream output cap (bounded by server setting).'),
    confirmation_id: z.string().max(64).optional().describe('ID returned by an earlier confirmation_required response, after a human approved it.'),
    confirm_token: z.string().max(64).optional().describe('One-time token a HUMAN copied from the dashboard (never guess this).'),
  };

  tool('execute_command',
    'Execute a shell command over SSH. Returns stdout/stderr separately, exit code and a result_id. Commands are classified read/modify/destructive; destructive ones return confirmation_required and only run after a human approves them in the dashboard, unless the server has auto-approve enabled (then the result has auto_approved=true).',
    execShape,
    async (a) => {
      const row = await resolveServer(env, a.server);
      const o = await runCommand(env, actor, row, a.command, a.timeout_seconds, { confirmationId: a.confirmation_id, confirmToken: a.confirm_token }, a.max_output_bytes);
      const v = outcomeView(o);
      return o.kind === 'blocked' ? { ...ok(v), isError: true } : ok(v);
    },
    { destructive: true, timeoutMs: 620_000 });

  tool('execute_commands',
    'Execute several commands sequentially (each classified separately). Stops at the first failure when stop_on_error is true, and at any command that needs human confirmation.',
    {
      server: serverArg,
      commands: z.array(z.string().min(1).max(16384)).min(1).max(20),
      timeout_seconds: z.number().int().min(1).max(600).optional(),
      stop_on_error: z.boolean().default(true),
    },
    async (a) => {
      const row = await resolveServer(env, a.server);
      const results: unknown[] = [];
      for (const cmd of a.commands) {
        const o = await runCommand(env, actor, row, cmd, a.timeout_seconds);
        results.push({ command: cmd, ...outcomeView(o) });
        if (o.kind !== 'done') break;
        if (a.stop_on_error && (o.value.status !== 'completed' || o.value.exitCode !== 0)) break;
      }
      return ok({ executed: results.length, total: a.commands.length, results });
    },
    { destructive: true, timeoutMs: 900_000 });

  tool('get_command_result', 'Fetch a stored command result by result_id.', { result_id: z.string().min(1).max(64) }, async ({ result_id }) => {
    const r = await env.DB.prepare('SELECT * FROM command_results WHERE id = ?').bind(result_id).first<Record<string, unknown>>();
    if (!r) return fail('result not found');
    return ok(r);
  }, { readOnly: true });

  // ---------------------------------------------------------------- files (SFTP)

  tool('list_directory', 'List a directory over SFTP (paginated).', {
    server: serverArg,
    path: z.string().min(1).max(4096).default('.'),
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(1000).default(200),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    return ok(await sshStub(env, row.id).sftpList(row.id, validateRemotePath(a.path), a.offset, a.limit));
  }, { readOnly: true });

  tool('read_file', 'Read a file over SFTP. Paginated: returns at most `length` bytes (≤1 MiB) from `offset`.', {
    server: serverArg,
    path: z.string().min(1).max(4096),
    offset: z.number().int().min(0).default(0),
    length: z.number().int().min(1).max(MAX_FILE_CHUNK).default(65536),
    encoding: z.enum(['utf8', 'base64']).default('utf8'),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    const r = await sshStub(env, row.id).sftpRead(row.id, validateRemotePath(a.path), a.offset, a.length);
    const content = a.encoding === 'base64' ? r.dataBase64 : new TextDecoder('utf-8', { fatal: false, ignoreBOM: false }).decode(Uint8Array.from(atob(r.dataBase64), (c) => c.charCodeAt(0)));
    return ok({ path: a.path, offset: a.offset, bytes: r.bytes, size: r.size, eof: r.eof, next_offset: r.eof ? null : a.offset + r.bytes, encoding: a.encoding, content });
  }, { readOnly: true });

  tool('write_file', 'Write a text (or base64) file over SFTP, replacing it (≤5 MiB). Blocked in read-only mode.', {
    server: serverArg,
    path: z.string().min(1).max(4096),
    content: z.string().max(MAX_WRITE * 2),
    encoding: z.enum(['utf8', 'base64']).default('utf8'),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    await checkFileOp(env, actor, row, 'modify', `write ${a.path}`);
    const b64 = a.encoding === 'base64' ? a.content : bytesToB64(new TextEncoder().encode(a.content));
    if (b64.length * 0.75 > MAX_WRITE) return fail('content exceeds 5 MiB');
    const r = await sshStub(env, row.id).sftpWrite(row.id, validateRemotePath(a.path), b64, 0, true);
    return ok({ path: a.path, bytes_written: r.bytes });
  }, { destructive: true });

  tool('upload_file', 'Upload base64 data to a remote path over SFTP. Use offset>0 to append chunks of a large file (first chunk offset=0 truncates).', {
    server: serverArg,
    path: z.string().min(1).max(4096),
    content_base64: z.string().max(Math.ceil((MAX_WRITE * 4) / 3) + 4),
    offset: z.number().int().min(0).default(0),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    await checkFileOp(env, actor, row, 'modify', `upload ${a.path}`);
    const r = await sshStub(env, row.id).sftpWrite(row.id, validateRemotePath(a.path), a.content_base64, a.offset, a.offset === 0);
    return ok({ path: a.path, offset: a.offset, bytes_written: r.bytes, next_offset: a.offset + r.bytes });
  }, { destructive: true });

  tool('download_file', 'Download a file chunk as base64 (≤1 MiB per call; use next_offset to continue).', {
    server: serverArg,
    path: z.string().min(1).max(4096),
    offset: z.number().int().min(0).default(0),
    length: z.number().int().min(1).max(MAX_FILE_CHUNK).default(MAX_FILE_CHUNK),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    const r = await sshStub(env, row.id).sftpRead(row.id, validateRemotePath(a.path), a.offset, a.length);
    return ok({ path: a.path, offset: a.offset, bytes: r.bytes, size: r.size, eof: r.eof, next_offset: r.eof ? null : a.offset + r.bytes, content_base64: r.dataBase64 });
  }, { readOnly: true });

  tool('create_directory', 'Create a directory over SFTP (parent must exist).', { server: serverArg, path: z.string().min(1).max(4096) }, async (a) => {
    const row = await resolveServer(env, a.server);
    await checkFileOp(env, actor, row, 'modify', `mkdir ${a.path}`);
    await sshStub(env, row.id).sftpMkdir(row.id, validateRemotePath(a.path));
    return ok({ created: a.path });
  });

  tool('rename_file', 'Rename / move a file or directory over SFTP.', { server: serverArg, from: z.string().min(1).max(4096), to: z.string().min(1).max(4096) }, async (a) => {
    const row = await resolveServer(env, a.server);
    await checkFileOp(env, actor, row, 'modify', `rename ${a.from}`);
    await sshStub(env, row.id).sftpRename(row.id, validateRemotePath(a.from), validateRemotePath(a.to));
    return ok({ from: a.from, to: a.to });
  });

  tool('delete_file', 'Delete a file or (empty, or with recursive=true) directory. Requires human approval (the first call returns confirmation_required) unless the server auto-approve setting covers it, in which case it runs immediately and the result says auto_approved=true.', {
    server: serverArg,
    path: z.string().min(1).max(4096),
    recursive: z.boolean().default(false),
    confirmation_id: z.string().max(64).optional(),
    confirm_token: z.string().max(64).optional(),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    const o = await deleteFile(env, actor, row, a.path, a.recursive, { confirmationId: a.confirmation_id, confirmToken: a.confirm_token });
    if (o.kind === 'done') return ok({ status: 'deleted', ...o.value, ...autoView(o.auto) });
    if (o.kind === 'blocked') return { ...ok({ status: 'blocked', reason: o.reason }), isError: true };
    return ok({ status: 'confirmation_required', confirmation_id: o.confirmation_id, expires_at: new Date(o.expires_at).toISOString(), ...(o.catastrophic ? { catastrophic: o.catastrophic } : {}), message: o.message });
  }, { destructive: true });

  // ---------------------------------------------------------------- metrics

  tool('get_cpu_usage', 'CPU utilisation (sampled over 1s from /proc/stat), load averages and core count.', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const r = await readCmd(env, actor, row, 'cat /proc/loadavg; nproc; head -1 /proc/stat; sleep 1; head -1 /proc/stat');
    const lines = r.stdout.trim().split('\n');
    const load = lines[0]?.split(/\s+/) ?? [];
    const parse = (l: string) => l.trim().split(/\s+/).slice(1).map(Number);
    const a = parse(lines[2] ?? ''), b = parse(lines[3] ?? '');
    const idle = (x: number[]) => (x[3] ?? 0) + (x[4] ?? 0);
    const total = (x: number[]) => x.slice(0, 8).reduce((s, v) => s + (v || 0), 0);
    const dt = total(b) - total(a);
    const usage = dt > 0 ? Math.round(((dt - (idle(b) - idle(a))) / dt) * 1000) / 10 : null;
    return ok({ usage_percent: usage, load_1m: Number(load[0]), load_5m: Number(load[1]), load_15m: Number(load[2]), cores: Number(lines[1]) });
  }, { readOnly: true });

  tool('get_memory_usage', 'Memory and swap usage from /proc/meminfo.', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const r = await readCmd(env, actor, row, 'cat /proc/meminfo');
    const m: Record<string, number> = {};
    for (const l of r.stdout.split('\n')) { const x = /^(\w+):\s+(\d+)/.exec(l); if (x) m[x[1]] = Number(x[2]) * 1024; }
    const used = m.MemTotal - (m.MemAvailable ?? m.MemFree);
    return ok({ total_bytes: m.MemTotal, available_bytes: m.MemAvailable, used_bytes: used, used_percent: m.MemTotal ? Math.round((used / m.MemTotal) * 1000) / 10 : null, swap_total_bytes: m.SwapTotal, swap_used_bytes: (m.SwapTotal ?? 0) - (m.SwapFree ?? 0) });
  }, { readOnly: true });

  tool('get_disk_usage', 'Filesystem usage (df).', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const r = await readCmd(env, actor, row, 'df -P -k -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -P -k');
    const fs = r.stdout.trim().split('\n').slice(1).map((l) => {
      const p = l.trim().split(/\s+/);
      return { filesystem: p[0], size_bytes: Number(p[1]) * 1024, used_bytes: Number(p[2]) * 1024, available_bytes: Number(p[3]) * 1024, used_percent: Number(String(p[4]).replace('%', '')), mount: p.slice(5).join(' ') };
    });
    return ok(fs);
  }, { readOnly: true });

  tool('get_system_uptime', 'System uptime and boot time.', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const r = await readCmd(env, actor, row, 'cat /proc/uptime; date +%s');
    const [up, now] = r.stdout.trim().split('\n');
    const secs = Math.floor(Number(up.split(/\s+/)[0]));
    return ok({ uptime_seconds: secs, uptime_human: `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h ${Math.floor((secs % 3600) / 60)}m`, boot_time: new Date((Number(now) - secs) * 1000).toISOString() });
  }, { readOnly: true });

  tool('get_running_processes', 'Top processes sorted by CPU or memory.', {
    server: serverArg,
    sort_by: z.enum(['cpu', 'memory']).default('cpu'),
    limit: z.number().int().min(1).max(200).default(25),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    const key = a.sort_by === 'cpu' ? '-%cpu' : '-%mem';
    const r = await readCmd(env, actor, row, `ps -eo pid,ppid,user,%cpu,%mem,rss,etime,comm --sort=${key} | head -n ${a.limit + 1}`);
    const procs = r.stdout.trim().split('\n').slice(1).map((l) => {
      const p = l.trim().split(/\s+/);
      return { pid: Number(p[0]), ppid: Number(p[1]), user: p[2], cpu_percent: Number(p[3]), mem_percent: Number(p[4]), rss_kb: Number(p[5]), elapsed: p[6], command: p.slice(7).join(' ') };
    });
    return ok(procs);
  }, { readOnly: true });

  tool('get_network_interfaces', 'Network interfaces, addresses and traffic counters.', { server: serverArg }, async ({ server }) => {
    const row = await resolveServer(env, server);
    const r = await readCmd(env, actor, row, 'ip -j addr 2>/dev/null || ip addr 2>/dev/null || ifconfig -a; echo "---NETDEV---"; cat /proc/net/dev');
    const [addrPart, devPart] = r.stdout.split('---NETDEV---');
    let interfaces: unknown;
    try {
      interfaces = (JSON.parse(addrPart) as Array<{ ifname: string; operstate: string; address?: string; mtu: number; addr_info?: Array<{ family: string; local: string; prefixlen: number }> }>).map((i) => ({ name: i.ifname, state: i.operstate, mac: i.address, mtu: i.mtu, addresses: (i.addr_info ?? []).map((x) => `${x.local}/${x.prefixlen}`) }));
    } catch {
      interfaces = addrPart.trim();
    }
    const counters = (devPart ?? '').trim().split('\n').slice(2).map((l) => {
      const [name, rest] = l.split(':');
      const n = rest.trim().split(/\s+/).map(Number);
      return { name: name.trim(), rx_bytes: n[0], rx_packets: n[1], tx_bytes: n[8], tx_packets: n[9] };
    });
    return ok({ interfaces, counters });
  }, { readOnly: true });

  tool('get_service_status', 'systemd status of a service.', { server: serverArg, service: z.string().min(1).max(128) }, async (a) => {
    const row = await resolveServer(env, a.server);
    const name = shQuote(validateServiceName(a.service));
    const r = await readCmd(env, actor, row, `systemctl show --no-pager -p Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID,ActiveEnterTimestamp,NRestarts -- ${name}; echo ---; systemctl status --no-pager -n 15 -- ${name} 2>&1 | tail -n 25`);
    const [props, status] = r.stdout.split('\n---\n');
    const o: Record<string, string> = {};
    for (const l of props.split('\n')) { const i = l.indexOf('='); if (i > 0) o[l.slice(0, i)] = l.slice(i + 1); }
    return ok({ properties: o, status_text: (status ?? '').trim() });
  }, { readOnly: true });

  // ---------------------------------------------------------------- docker

  tool('docker_ps', 'List Docker containers.', { server: serverArg, all: z.boolean().default(false) }, async (a) => {
    const row = await resolveServer(env, a.server);
    const r = await readCmd(env, actor, row, `docker ps ${a.all ? '-a ' : ''}--no-trunc --format '{{json .}}'`);
    if (r.exitCode !== 0) return fail(r.stderr.trim() || `docker ps exited ${r.exitCode}`);
    return ok(r.stdout.trim().split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return l; } }));
  }, { readOnly: true });

  tool('docker_logs', 'Recent logs of a container (stdout and stderr kept separate).', {
    server: serverArg,
    container: z.string().min(1).max(128),
    tail: z.number().int().min(1).max(5000).default(200),
    since: z.string().regex(/^[0-9]+[smhd]$|^\d{4}-\d{2}-\d{2}(T[0-9:.Z+-]+)?$/).optional().describe('e.g. 10m, 2h, or an RFC3339 date'),
    timestamps: z.boolean().default(false),
  }, async (a) => {
    const row = await resolveServer(env, a.server);
    const c = shQuote(validateContainerRef(a.container));
    const r = await readCmd(env, actor, row, `docker logs --tail ${a.tail}${a.since ? ` --since ${shQuote(a.since)}` : ''}${a.timestamps ? ' --timestamps' : ''} ${c}`, 60);
    if (r.exitCode !== 0 && !r.stdout) return fail(r.stderr.trim() || `docker logs exited ${r.exitCode}`);
    return ok({ container: a.container, stdout: r.stdout, stderr: r.stderr, truncated: r.stdoutTruncated || r.stderrTruncated });
  }, { readOnly: true });

  tool('docker_inspect', 'docker inspect output for a container.', { server: serverArg, container: z.string().min(1).max(128) }, async (a) => {
    const row = await resolveServer(env, a.server);
    const r = await readCmd(env, actor, row, `docker inspect ${shQuote(validateContainerRef(a.container))}`);
    if (r.exitCode !== 0) return fail(r.stderr.trim() || `docker inspect exited ${r.exitCode}`);
    try { return ok(JSON.parse(r.stdout)); } catch { return ok(r.stdout); }
  }, { readOnly: true });

  void getSettings;
}

function bytesToB64(u: Uint8Array): string {
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
}

export const TOOL_NAMES = [
  'list_servers', 'get_server_status', 'test_ssh_connection', 'get_server_info', 'execute_command', 'execute_commands', 'get_command_result',
  'list_directory', 'read_file', 'write_file', 'upload_file', 'download_file', 'create_directory', 'rename_file', 'delete_file',
  'get_cpu_usage', 'get_memory_usage', 'get_disk_usage', 'get_system_uptime', 'get_running_processes', 'get_network_interfaces',
  'get_service_status', 'docker_ps', 'docker_logs', 'docker_inspect',
];
