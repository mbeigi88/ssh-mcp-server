import type { Env } from '../env';

/**
 * Fixed-window rate limiter backed by D1 (single atomic UPSERT ... RETURNING).
 * Returns true when the request is allowed.
 */
export async function rateLimit(env: Env, key: string, limit: number, windowSeconds: number): Promise<{ ok: boolean; remaining: number; retryAfter: number }> {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - (now % windowSeconds);
  const row = await env.DB.prepare(
    'INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1) ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1 RETURNING count',
  )
    .bind(key, windowStart)
    .first<{ count: number }>();
  const count = row?.count ?? 1;
  // opportunistic cleanup of old windows (1% of calls)
  if (Math.random() < 0.01) {
    await env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(now - 86400).run().catch(() => {});
  }
  return { ok: count <= limit, remaining: Math.max(0, limit - count), retryAfter: windowStart + windowSeconds - now };
}
