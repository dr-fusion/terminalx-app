const WINDOW_MS = 60_000;
const MAX_ATTEMPTS = 5;
const MAX_KEYS = 10_000;

const buckets = new Map<string, number[]>();

export function isRateLimited(key: string): boolean {
  const now = Date.now();
  const attempts = buckets.get(key) ?? [];
  const recent = attempts.filter((t) => now - t < WINDOW_MS);

  if (recent.length >= MAX_ATTEMPTS) {
    buckets.set(key, recent);
    return true;
  }

  if (!buckets.has(key) && buckets.size >= MAX_KEYS) {
    const oldest = buckets.keys().next().value;
    if (oldest !== undefined) buckets.delete(oldest);
  }

  recent.push(now);
  buckets.set(key, recent);
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, attempts] of buckets) {
    const recent = attempts.filter((t) => now - t < WINDOW_MS);
    if (recent.length === 0) buckets.delete(key);
    else buckets.set(key, recent);
  }
}, 300_000).unref?.();

export function clientIp(req: { headers: { get(name: string): string | null } }): string {
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0]!.trim();
  const real = req.headers.get("x-real-ip");
  if (real) return real.trim();
  return "unknown";
}
