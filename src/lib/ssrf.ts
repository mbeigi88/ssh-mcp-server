// SSRF protection for SSH targets. Hostnames are resolved via DNS-over-HTTPS and every
// address is checked; we then connect to the *validated IP* (not the hostname) so a DNS
// rebinding between check and connect cannot redirect the socket.

export type Resolver = (hostname: string) => Promise<string[]>;

export class TargetBlockedError extends Error {
  constructor(msg: string) { super(msg); this.name = 'TargetBlockedError'; }
}

export function isIPv4(s: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  return !!m && m.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o);
}

export function isIPv6(s: string): boolean {
  return s.includes(':') && /^[0-9a-fA-F:.]+$/.test(s) && expandIPv6(s) !== null;
}

function v4ToInt(s: string): number {
  return s.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}

const V4_BLOCKS: Array<[string, number, string]> = [
  ['0.0.0.0', 8, 'this-network'],
  ['10.0.0.0', 8, 'private (RFC1918)'],
  ['100.64.0.0', 10, 'carrier-grade NAT'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local / cloud metadata'],
  ['172.16.0.0', 12, 'private (RFC1918)'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'TEST-NET-1'],
  ['192.88.99.0', 24, '6to4 relay'],
  ['192.168.0.0', 16, 'private (RFC1918)'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'TEST-NET-2'],
  ['203.0.113.0', 24, 'TEST-NET-3'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
  ['255.255.255.255', 32, 'broadcast'],
];

export function classifyIPv4(ip: string): string | null {
  const n = v4ToInt(ip);
  for (const [base, bits, label] of V4_BLOCKS) {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    if ((n & mask) === (v4ToInt(base) & mask)) return label;
  }
  return null;
}

function expandIPv6(s: string): number[] | null {
  let str = s.toLowerCase();
  const zone = str.indexOf('%');
  if (zone >= 0) str = str.slice(0, zone);
  const lastColon = str.lastIndexOf(':');
  if (lastColon < 0) return null;
  const maybeV4 = str.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    if (!isIPv4(maybeV4)) return null;
    const n = v4ToInt(maybeV4);
    str = str.slice(0, lastColon + 1) + (n >>> 16).toString(16) + ':' + (n & 0xffff).toString(16);
  }
  const parts = str.split('::');
  if (parts.length > 2) return null;
  const parse = (x: string) => (x ? x.split(':') : []);
  const head = parse(parts[0]);
  const rest = parts.length === 2 ? parse(parts[1]) : [];
  const all = [...head, ...rest];
  if (all.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  if (parts.length === 1 && all.length !== 8) return null;
  if (parts.length === 2 && all.length > 7) return null;
  const n = (g: string) => parseInt(g, 16);
  return parts.length === 2
    ? [...head.map(n), ...new Array(8 - all.length).fill(0), ...rest.map(n)]
    : all.map(n);
}

export function classifyIPv6(ip: string): string | null {
  const g = expandIPv6(ip);
  if (!g) return 'invalid IPv6';
  if (g.every((x) => x === 0)) return 'unspecified';
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'loopback';
  // IPv4-mapped ::ffff:a.b.c.d and IPv4-compatible / NAT64 (64:ff9b::/96)
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    const v4 = `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
    return classifyIPv4(v4) ? `IPv4-mapped ${classifyIPv4(v4)}` : null;
  }
  if (g[0] === 0x64 && g[1] === 0xff9b) {
    const v4 = `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
    return classifyIPv4(v4) ? `NAT64 ${classifyIPv4(v4)}` : null;
  }
  if ((g[0] & 0xfe00) === 0xfc00) return 'unique local (fc00::/7)';
  if ((g[0] & 0xffc0) === 0xfe80) return 'link-local';
  if ((g[0] & 0xffc0) === 0xfec0) return 'site-local';
  if ((g[0] & 0xff00) === 0xff00) return 'multicast';
  if (g[0] === 0x2001 && g[1] === 0x0db8) return 'documentation';
  if (g[0] === 0x2002) return '6to4';
  if (g[0] === 0x2001 && g[1] === 0) return 'Teredo';
  if (g[0] === 0xfd00 && g[1] === 0x0ec2) return 'cloud metadata';
  return null;
}

export function classifyIP(ip: string): string | null {
  if (isIPv4(ip)) return classifyIPv4(ip);
  if (isIPv6(ip)) return classifyIPv6(ip);
  return 'not an IP address';
}

const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;
const BLOCKED_NAMES = /(^|\.)(localhost|localdomain|internal|local|metadata\.google\.internal|metadata)$/i;

export function isValidHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '');
  return isIPv4(h) || isIPv6(h) || HOSTNAME_RE.test(h);
}

/** DNS-over-HTTPS resolver (Cloudflare 1.1.1.1 JSON API). */
export const dohResolver: Resolver = async (hostname) => {
  const out: string[] = [];
  for (const type of ['A', 'AAAA']) {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`, {
      headers: { accept: 'application/dns-json' },
    });
    if (!res.ok) throw new Error(`DNS lookup failed (${res.status})`);
    const j = (await res.json()) as { Answer?: Array<{ type: number; data: string }> };
    for (const a of j.Answer ?? []) {
      if ((a.type === 1 && type === 'A') || (a.type === 28 && type === 'AAAA')) out.push(a.data);
    }
  }
  return out;
};

export interface ResolvedTarget {
  /** address to actually connect to (validated IP, or hostname when private targets are allowed in dev) */
  connectHost: string;
  addresses: string[];
}

export async function resolveAndCheckTarget(host: string, allowPrivate: boolean, resolver: Resolver = dohResolver): Promise<ResolvedTarget> {
  const h = host.trim().replace(/^\[|\]$/g, '');
  if (!isValidHost(h)) throw new TargetBlockedError(`invalid host: ${host}`);
  if (isIPv4(h) || isIPv6(h)) {
    const why = classifyIP(h);
    if (why && !allowPrivate) throw new TargetBlockedError(`target ${h} is blocked (${why}); enable "allow private targets" to permit it`);
    return { connectHost: h, addresses: [h] };
  }
  if (BLOCKED_NAMES.test(h.replace(/\.$/, '')) && !allowPrivate) {
    throw new TargetBlockedError(`hostname ${h} is blocked (internal name)`);
  }
  let addrs: string[];
  try {
    addrs = await resolver(h);
  } catch (e) {
    if (allowPrivate) return { connectHost: h, addresses: [] };
    throw new TargetBlockedError(`could not resolve ${h}: ${(e as Error).message}`);
  }
  if (addrs.length === 0) throw new TargetBlockedError(`hostname ${h} did not resolve`);
  if (!allowPrivate) {
    for (const a of addrs) {
      const why = classifyIP(a);
      if (why) throw new TargetBlockedError(`hostname ${h} resolves to ${a} which is blocked (${why})`);
    }
  }
  const v4 = addrs.find(isIPv4);
  return { connectHost: v4 ?? addrs[0], addresses: addrs };
}
