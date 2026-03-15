const apiLimiter = new Map();

const DEFAULT_LIMIT = 60;
const DEFAULT_WINDOW_MS = 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_KEY_LENGTH = 200;

const CLEANUP_INTERVAL_MS = 60 * 1000;
const PENALTY_BASE_MS = 5 * 60 * 1000;
const MAX_PENALTY_MS = 60 * 60 * 1000;

let lastCleanupAt = 0;

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function normalizePositiveInteger(value, fallback) {
  const num = Math.floor(safeNumber(value, fallback));
  return num >= 0 ? num : fallback;
}

function normalizeKey(input) {
  const key = String(input || "").trim().slice(0, MAX_KEY_LENGTH);
  return key || "unknown";
}

function normalizeRoute(route) {
  return String(route || "unknown-route").trim().toLowerCase().slice(0, 150);
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

function createEmptyRecord(now) {
  return {
    count: 0,
    start: now,
    updatedAt: now,
    violations: 0,
    penaltyUntil: 0,
    lastRoute: "unknown-route"
  };
}

function getRouteWeight(route) {
  const normalized = normalizeRoute(route);

  if (
    normalized.includes("login") ||
    normalized.includes("signup") ||
    normalized.includes("verify") ||
    normalized.includes("developer") ||
    normalized.includes("admin") ||
    normalized.includes("security-log")
  ) {
    return 2;
  }

  return 1;
}

function getRecommendedAction({ allowed, penaltyActive, overBy }) {
  if (penaltyActive) {
    return "block";
  }

  if (!allowed && overBy >= 10) {
    return "challenge";
  }

  if (!allowed) {
    return "throttle";
  }

  return "allow";
}

function applyPenalty(record, now) {
  const violations = normalizePositiveInteger(record.violations, 0);
  const penaltyMs = Math.min(
    MAX_PENALTY_MS,
    PENALTY_BASE_MS + violations * 5 * 60 * 1000
  );

  record.penaltyUntil = now + penaltyMs;
}

export function checkApiRateLimit(options = {}) {
  cleanupStaleEntries();

  const now = Date.now();

  let key = "unknown";
  let limit = DEFAULT_LIMIT;
  let windowMs = DEFAULT_WINDOW_MS;
  let route = "unknown-route";

  if (typeof options === "string") {
    key = normalizeKey(options);
  } else {
    key = normalizeKey(options.key);
    limit = normalizePositiveInteger(options.limit, DEFAULT_LIMIT);
    windowMs = normalizePositiveInteger(options.windowMs, DEFAULT_WINDOW_MS);
    route = normalizeRoute(options.route);
  }

  const routeWeight = getRouteWeight(route);

  let record = apiLimiter.get(key);

  if (!record) {
    record = createEmptyRecord(now);
  }

  if (now - safeNumber(record.start, now) >= windowMs) {
    record.count = 0;
    record.start = now;
  }

  const penaltyActive = safeNumber(record.penaltyUntil) > now;

  record.count = normalizePositiveInteger(record.count, 0);
  record.count += routeWeight;
  record.updatedAt = now;
  record.lastRoute = route;

  let allowed = record.count <= limit && !penaltyActive;

  if (!allowed && !penaltyActive) {
    record.violations = normalizePositiveInteger(record.violations, 0) + 1;

    if (record.violations >= 3) {
      applyPenalty(record, now);
    }
  }

  apiLimiter.set(key, record);

  const overBy = Math.max(0, record.count - limit);
  const remaining = Math.max(0, limit - record.count);
  const penaltyRemainingMs = penaltyActive
    ? Math.max(0, safeNumber(record.penaltyUntil) - now)
    : 0;

  const remainingMs = penaltyActive
    ? penaltyRemainingMs
    : allowed
      ? 0
      : Math.max(0, windowMs - (now - record.start));

  const recommendedAction = getRecommendedAction({
    allowed,
    penaltyActive,
    overBy
  });

  return {
    allowed,
    recommendedAction,
    remaining,
    remainingMs,
    limit,
    count: record.count,
    overBy,
    windowMs,
    resetAt: record.start + windowMs,
    penaltyActive,
    penaltyUntil: safeNumber(record.penaltyUntil) || 0,
    violations: normalizePositiveInteger(record.violations, 0),
    routeWeight
  };
}
