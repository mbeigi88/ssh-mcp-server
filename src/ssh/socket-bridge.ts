// Bridges a Cloudflare `cloudflare:sockets` Socket to a Node.js Duplex stream,
// which is what ssh2's `sock` option expects.
import { connect } from 'cloudflare:sockets';
import { Duplex } from 'node:stream';
import { Buffer } from 'node:buffer';

export interface BridgeOptions {
  hostname: string;
  port: number;
  connectTimeoutMs: number;
}

export async function openTcpDuplex(opts: BridgeOptions): Promise<Duplex> {
  const socket = connect({ hostname: opts.hostname, port: opts.port }, { allowHalfOpen: false });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, rej) => {
        timer = setTimeout(() => rej(new Error(`TCP connect timeout after ${opts.connectTimeoutMs}ms`)), opts.connectTimeoutMs);
      }),
    ]);
  } catch (e) {
    socket.close().catch(() => {}); // do not await: close() of a pending connect can hang
    throw e instanceof Error ? e : new Error(String(e));
  } finally {
    if (timer) clearTimeout(timer);
  }

  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let destroyed = false;

  const duplex = new Duplex({
    read() { /* data is pushed by the pump below */ },
    write(chunk: Buffer, _enc, cb) {
      writer.write(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)).then(() => cb(), (err) => cb(err));
    },
    final(cb) {
      writer.close().then(() => cb(), () => cb());
    },
    destroy(err, cb) {
      destroyed = true;
      try { reader.cancel().catch(() => {}); } catch { /* ignore */ }
      socket.close().catch(() => {});
      cb(err);
    },
  });

  (async () => {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) duplex.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
      }
      if (!destroyed) duplex.push(null);
    } catch (err) {
      if (!destroyed) duplex.destroy(err instanceof Error ? err : new Error(String(err)));
    }
  })();

  // ssh2 calls these on net.Socket; provide no-op shims.
  (duplex as unknown as { setNoDelay: () => void }).setNoDelay = () => {};
  (duplex as unknown as { setKeepAlive: () => void }).setKeepAlive = () => {};
  return duplex;
}
