import { redis } from "./_redis.js";

const DEFAULT_LIMIT = 60;
const DEFAULT_WINDOW_MS = 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_KEY_LENGTH = 200;

const PENALTY_BASE_MS = 5 * 60 * 1000;
const MAX_PENALTY_MS = 2 * 60 * 60 * 1000;

const BURST_WINDOW_MS = 15 * 1000;
const VIOLATION_DECAY_MS = 30 * 60 * 1000;

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

function buildRedisKey(key) {
  return `ratelimit:${normalizeKey(key)}`;
}

function createEmptyRecord(now) {
  return {
    count: 0,
    start: now,
    updatedAt: now,
    violations: 0,
    penaltyUntil: 0,
    lastViolationAt: 0,
    lastRoute: "unknown-route",
    highestCountSeen: 0,
    recentHits: []
  };
}

function getRouteSensitivity(route) {
  const normalized = normalizeRoute(route);

  if (
    normalized.includes("admin") ||
    normalized.includes("developer") ||
    normalized.includes("role") ||
    normalized.includes("claims")
  ) {
    return "critical";
  }

  if (
    normalized.includes("login") ||
    normalized.includes("signup") ||
    normalized.includes("verify") ||
    normalized.includes("security-log")
  ) {
    return "high";
  }

  return "normal";
}

function getRouteWeight(route) {
  const sensitivity = getRouteSensitivity(route);

  if (sensitivity === "critical") return 3;
  if (sensitivity === "high") return 2;
  return 1;
}

function getRecommendedAction({
  allowed,
  penaltyActive,
  overBy,
  violations,
  routeSensitivity,
  burstCount
}) {
  if (penaltyActive) {
    return "block";
  }

  if (
    !allowed &&
    (
      routeSensitivity === "critical" ||
      violations >= 4 ||
      overBy >= 15 ||
      burstCount >= 12
    )
  ) {
    return "block";
  }

  if (
    !allowed &&
    (
      violations >= 2 ||
      overBy >= 8 ||
      burstCount >= 8
    )
  ) {
    return "challenge";
  }

  if (!allowed) {
    return "throttle";
  }

  return "allow";
}

function decayViolations(record, now) {
  if (
    safeNumber(record.lastViolationAt, 0) > 0 &&
    now - safeNumber(record.lastViolationAt, 0) > VIOLATION_DECAY_MS &&
    safeNumber(record.violations, 0) > 0
  ) {
    record.violations = Math.max(0, normalizePositiveInteger(record.violations, 0) - 1);
    record.lastViolationAt = now;
  }
}

function applyPenalty(record, now, routeSensitivity = "normal") {
  const violations = normalizePositiveInteger(record.violations, 0);

  let multiplier = 1;
  if (routeSensitivity === "critical") multiplier = 2;
  else if (routeSensitivity === "high") multiplier = 1.4;

  const penaltyMs = Math.min(
    MAX_PENALTY_MS,
    Math.floor((PENALTY_BASE_MS + violations * 7 * 60 * 1000) * multiplier)
  );

  record.penaltyUntil = now + penaltyMs;
}

function updateBurstMemory(record, now) {
  if (!Array.isArray(record.recentHits)) {
    record.recentHits = [];
  }

  record.recentHits.push(now);
  record.recentHits = record.recentHits
    .filter((ts) => now - safeNumber(ts, 0) <= BURST_WINDOW_MS)
    .slice(-50);

  return record.recentHits.length;
}

async function getStoredRecord(redisKey) {
  try {
    const raw = await redis.get(redisKey);

    if (!raw) {
      return null;
    }

    if (typeof raw === "string") {
      return JSON.parse(raw);
    }

    if (typeof raw === "object") {
      return raw;
    }

    return null;
  } catch (error) {
    console.error("Redis rate-limit read failed:", error);
    return null;
  }
}

async function storeRecord(redisKey, record) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(STALE_TTL_MS / 1000));
    await redis.set(redisKey, JSON.stringify(record), { ex: ttlSeconds });
    return true;
  } catch (error) {
    console.error("Redis rate-limit write failed:", error);
    return false;
  }
}

export async function checkApiRateLimit(options = {}) {
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

  const routeSensitivity = getRouteSensitivity(route);
  const routeWeight = getRouteWeight(route);
  const redisKey = buildRedisKey(key);

  let record = await getStoredRecord(redisKey);

  if (!record) {
    record = createEmptyRecord(now);
  }

  decayViolations(record, now);

  if (now - safeNumber(record.start, now) >= windowMs) {
    record.count = 0;
    record.start = now;
  }

  const penaltyActive = safeNumber(record.penaltyUntil) > now;

  record.count = normalizePositiveInteger(record.count, 0);
  record.count += routeWeight;
  record.updatedAt = now;
  record.lastRoute = route;
  record.highestCountSeen = Math.max(
    normalizePositiveInteger(record.highestCountSeen, 0),
    normalizePositiveInteger(record.count, 0)
  );

  const burstCount = updateBurstMemory(record, now);

  let allowed = record.count <= limit && !penaltyActive;

  if (!allowed && !penaltyActive) {
    record.violations = normalizePositiveInteger(record.violations, 0) + 1;
    record.lastViolationAt = now;

    if (
      record.violations >= 3 ||
      burstCount >= 10 ||
      (routeSensitivity === "critical" && record.violations >= 2)
    ) {
      applyPenalty(record, now, routeSensitivity);
    }
  }

  await storeRecord(redisKey, record);

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
    overBy,
    violations: normalizePositiveInteger(record.violations, 0),
    routeSensitivity,
    burstCount
  });

  let containmentAction = "none";
  if (recommendedAction === "block") {
    containmentAction = routeSensitivity === "critical"
      ? "freeze_sensitive_route"
      : "temporary_containment";
  } else if (recommendedAction === "challenge") {
    containmentAction = "step_up_verification";
  } else if (recommendedAction === "throttle") {
    containmentAction = "slow_down_actor";
  }

  return {
    allowed,
    recommendedAction,
    containmentAction,
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
    routeWeight,
    routeSensitivity,
    burstCount,
    highestCountSeen: normalizePositiveInteger(record.highestCountSeen, 0)
  };
}
