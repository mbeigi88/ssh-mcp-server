// POSIX-shell-safe argument quoting for every command this server builds itself.
// Single quotes disable all expansion; an embedded ' becomes '\''.

export function shQuote(arg: string): string {
  assertSafeArg(arg);
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** Rejects NUL bytes and line breaks, which can never be part of a safe single argument. */
export function assertSafeArg(arg: string): void {
  if (typeof arg !== 'string') throw new Error('argument must be a string');
  if (/[\0\r\n]/.test(arg)) throw new Error('argument contains a NUL byte or line break');
}

/** Validates a remote path used in SFTP or tool-built commands. */
export function validateRemotePath(p: string, maxLen = 4096): string {
  if (typeof p !== 'string' || p.length === 0) throw new Error('path is required');
  if (p.length > maxLen) throw new Error('path too long');
  assertSafeArg(p);
  return p;
}

const SERVICE_RE = /^[A-Za-z0-9@._:\\-]{1,128}$/;
export function validateServiceName(name: string): string {
  if (!SERVICE_RE.test(name)) throw new Error('invalid service name');
  return name;
}

const CONTAINER_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
export function validateContainerRef(name: string): string {
  if (!CONTAINER_RE.test(name)) throw new Error('invalid container name or id');
  return name;
}
