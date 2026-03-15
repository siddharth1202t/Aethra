const apiLimiter = new Map();

const DEFAULT_LIMIT = 60;
const DEFAULT_WINDOW_MS = 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function cleanupStaleEntries() {
  const now = Date.now();

  for (const [key, record] of apiLimiter.entries()) {
    if (!record || now - safeNumber(record.updatedAt) > STALE_TTL_MS) {
      apiLimiter.delete(key);
    }
  }
}

function normalizeKey(input) {
  const key = String(input || "").trim();
  return key || "unknown";
}

export function checkApiRateLimit(options = {}) {
  cleanupStaleEntries();

  const now = Date.now();

  let key;
  let limit = DEFAULT_LIMIT;
  let windowMs = DEFAULT_WINDOW_MS;

  if (typeof options === "string") {
    key = normalizeKey(options);
  } else {
    key = normalizeKey(options.key);
    limit = safeNumber(options.limit, DEFAULT_LIMIT);
    windowMs = safeNumber(options.windowMs, DEFAULT_WINDOW_MS);
  }

  let record = apiLimiter.get(key);

  if (!record) {
    record = {
      count: 0,
      start: now,
      updatedAt: now
    };
  }

  if (now - record.start >= windowMs) {
    record.count = 0;
    record.start = now;
  }

  record.count += 1;
  record.updatedAt = now;

  apiLimiter.set(key, record);

  const allowed = record.count <= limit;
  const remaining = Math.max(0, limit - record.count);
  const remainingMs = allowed ? 0 : Math.max(0, windowMs - (now - record.start));

  return {
    allowed,
    remaining,
    remainingMs,
    limit,
    count: record.count,
    windowMs,
    resetAt: record.start + windowMs
  };
}
