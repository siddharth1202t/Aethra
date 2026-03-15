const apiLimiter = new Map();

const DEFAULT_LIMIT = 60;
const DEFAULT_WINDOW_MS = 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_KEY_LENGTH = 200;

let lastCleanupAt = 0;
const CLEANUP_INTERVAL_MS = 60 * 1000;

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function normalizePositiveInteger(value, fallback) {
  const num = Math.floor(safeNumber(value, fallback));
  return num > 0 ? num : fallback;
}

function normalizeKey(input) {
  const key = String(input || "").trim().slice(0, MAX_KEY_LENGTH);
  return key || "unknown";
}

function cleanupStaleEntries(force = false) {
  const now = Date.now();

  if (!force && now - lastCleanupAt < CLEANUP_INTERVAL_MS) {
    return;
  }

  lastCleanupAt = now;

  for (const [key, record] of apiLimiter.entries()) {
    if (!record || now - safeNumber(record.updatedAt) > STALE_TTL_MS) {
      apiLimiter.delete(key);
    }
  }
}

export function checkApiRateLimit(options = {}) {
  cleanupStaleEntries();

  const now = Date.now();

  let key = "unknown";
  let limit = DEFAULT_LIMIT;
  let windowMs = DEFAULT_WINDOW_MS;

  if (typeof options === "string") {
    key = normalizeKey(options);
  } else {
    key = normalizeKey(options.key);
    limit = normalizePositiveInteger(options.limit, DEFAULT_LIMIT);
    windowMs = normalizePositiveInteger(options.windowMs, DEFAULT_WINDOW_MS);
  }

  let record = apiLimiter.get(key);

  if (!record) {
    record = {
      count: 0,
      start: now,
      updatedAt: now
    };
  }

  if (now - safeNumber(record.start, now) >= windowMs) {
    record.count = 0;
    record.start = now;
  }

  record.count = normalizePositiveInteger(record.count, 0);
  record.count += 1;
  record.updatedAt = now;

  apiLimiter.set(key, record);

  const allowed = record.count <= limit;
  const remaining = Math.max(0, limit - record.count);
  const remainingMs = allowed
    ? 0
    : Math.max(0, windowMs - (now - record.start));

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
