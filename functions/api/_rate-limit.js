import { getRedis } from "./_redis.js";

const DEFAULT_LIMIT = 60;
const DEFAULT_WINDOW_MS = 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_KEY_LENGTH = 200;

const PENALTY_BASE_MS = 5 * 60 * 1000;
const MAX_PENALTY_MS = 2 * 60 * 60 * 1000;
const PENALTY_REAPPLY_GUARD_MS = 60 * 1000;

const BURST_WINDOW_MS = 15 * 1000;
const VIOLATION_DECAY_MS = 30 * 60 * 1000;

const MAX_LIMIT = 10_000;
const MAX_WINDOW_MS = 24 * 60 * 60 * 1000;

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function normalizePositiveInteger(value, fallback = 0, max = 1_000_000) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num) || num < 0) return fallback;
  return Math.min(num, max);
}

function safeTimestamp(value, fallback = 0) {
  return normalizePositiveInteger(value, fallback, Date.now() + 60_000);
}

function safeString(value, maxLength = 300) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function normalizeKey(input) {
  const key = safeString(input || "", MAX_KEY_LENGTH).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  return key || "unknown";
}

function normalizeRoute(route) {
  const raw = safeString(route || "unknown-route", 300);

  if (!raw) return "unknown-route";

  const cleaned = raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .trim()
    .toLowerCase()
    .slice(0, 150);

  return cleaned || "unknown-route";
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
    lastPenaltyAppliedAt: 0,
    lastRoute: "unknown-route",
    highestCountSeen: 0,
    recentHits: []
  };
}

function normalizeRecord(raw, now) {
  const record = raw && typeof raw === "object" ? raw : {};

  return {
    count: normalizePositiveInteger(record.count, 0),
    start: safeTimestamp(record.start, now),
    updatedAt: safeTimestamp(record.updatedAt, now),
    violations: normalizePositiveInteger(record.violations, 0),
    penaltyUntil: safeTimestamp(record.penaltyUntil, 0),
    lastViolationAt: safeTimestamp(record.lastViolationAt, 0),
    lastPenaltyAppliedAt: safeTimestamp(record.lastPenaltyAppliedAt, 0),
    lastRoute: normalizeRoute(record.lastRoute || "unknown-route"),
    highestCountSeen: normalizePositiveInteger(record.highestCountSeen, 0),
    recentHits: Array.isArray(record.recentHits)
      ? record.recentHits
          .map((ts) => safeTimestamp(ts, 0))
          .filter((ts) => ts > 0 && now - ts <= BURST_WINDOW_MS)
          .slice(-50)
      : []
  };
}

function getRouteSensitivity(route) {
  const normalized = normalizeRoute(route);

  if (
    normalized.includes("admin") ||
    normalized.includes("developer") ||
    normalized.includes("role") ||
    normalized.includes("claims") ||
    normalized.includes("security") ||
    normalized.includes("containment") ||
    normalized.includes("metrics")
  ) {
    return "critical";
  }

  if (
    normalized.includes("login") ||
    normalized.includes("signup") ||
    normalized.includes("verify") ||
    normalized.includes("auth") ||
    normalized.includes("password") ||
    normalized.includes("session")
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
  const lastViolationAt = safeTimestamp(record.lastViolationAt, 0);
  const violations = normalizePositiveInteger(record.violations, 0);

  if (
    lastViolationAt > 0 &&
    now - lastViolationAt > VIOLATION_DECAY_MS &&
    violations > 0
  ) {
    const decaySteps = Math.floor((now - lastViolationAt) / VIOLATION_DECAY_MS);
    record.violations = Math.max(0, violations - Math.max(1, decaySteps));
    record.lastViolationAt = now;
  }
}

function shouldApplyPenalty(record, now) {
  const lastPenaltyAppliedAt = safeTimestamp(record.lastPenaltyAppliedAt, 0);
  return now - lastPenaltyAppliedAt >= PENALTY_REAPPLY_GUARD_MS;
}

function applyPenalty(record, now, routeSensitivity = "normal") {
  const violations = normalizePositiveInteger(record.violations, 0);
  const existingPenaltyUntil = safeTimestamp(record.penaltyUntil, 0);
  const activePenaltyRemaining = Math.max(0, existingPenaltyUntil - now);

  let multiplier = 1;
  if (routeSensitivity === "critical") multiplier = 2;
  else if (routeSensitivity === "high") multiplier = 1.4;

  const penaltyMs = Math.min(
    MAX_PENALTY_MS,
    Math.floor(
      Math.max(
        PENALTY_BASE_MS + violations * 7 * 60 * 1000,
        activePenaltyRemaining > 0 ? activePenaltyRemaining * 1.35 : 0
      ) * multiplier
    )
  );

  record.penaltyUntil = now + penaltyMs;
  record.lastPenaltyAppliedAt = now;
  return penaltyMs;
}

function updateBurstMemory(record, now) {
  if (!Array.isArray(record.recentHits)) {
    record.recentHits = [];
  }

  record.recentHits.push(now);
  record.recentHits = record.recentHits
    .filter((ts) => now - safeTimestamp(ts, 0) <= BURST_WINDOW_MS)
    .slice(-50);

  return record.recentHits.length;
}

async function getStoredRecord(redis, redisKey, now) {
  try {
    const raw = await redis.get(redisKey);

    if (!raw) return null;

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      if (!parsed || typeof parsed !== "object") return null;
      return normalizeRecord(parsed, now);
    }

    if (typeof raw === "object") {
      return normalizeRecord(raw, now);
    }

    return null;
  } catch (error) {
    console.error("Redis rate-limit read failed:", error);
    return null;
  }
}

async function storeRecord(redis, redisKey, record) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(STALE_TTL_MS / 1000));
    const normalized = normalizeRecord(record, Date.now());
    await redis.set(redisKey, JSON.stringify(normalized), { ex: ttlSeconds });
    return true;
  } catch (error) {
    console.error("Redis rate-limit write failed:", error);
    return false;
  }
}

export async function checkApiRateLimit(options = {}) {
  const now = Date.now();

  let env = {};
  let key = "unknown";
  let limit = DEFAULT_LIMIT;
  let windowMs = DEFAULT_WINDOW_MS;
  let route = "unknown-route";

  if (typeof options === "string") {
    key = normalizeKey(options);
  } else {
    env = options.env || {};
    key = normalizeKey(options.key);
    limit = Math.max(1, Math.min(MAX_LIMIT, normalizePositiveInteger(options.limit, DEFAULT_LIMIT)));
    windowMs = Math.max(1_000, Math.min(MAX_WINDOW_MS, normalizePositiveInteger(options.windowMs, DEFAULT_WINDOW_MS)));
    route = normalizeRoute(options.route);
  }

  const redis = getRedis(env);
  const routeSensitivity = getRouteSensitivity(route);
  const routeWeight = getRouteWeight(route);
  const redisKey = buildRedisKey(key);

  let record = await getStoredRecord(redis, redisKey, now);
  if (!record) {
    record = createEmptyRecord(now);
  }

  decayViolations(record, now);

  if (now - safeTimestamp(record.start, now) >= windowMs) {
    record.count = 0;
    record.start = now;
  }

  const penaltyActiveBefore = safeTimestamp(record.penaltyUntil, 0) > now;

  record.count = normalizePositiveInteger(record.count, 0) + routeWeight;
  record.updatedAt = now;
  record.lastRoute = route;
  record.highestCountSeen = Math.max(
    normalizePositiveInteger(record.highestCountSeen, 0),
    normalizePositiveInteger(record.count, 0)
  );

  const burstCount = updateBurstMemory(record, now);

  let allowed = record.count <= limit && !penaltyActiveBefore;
  let penaltyApplied = false;
  let penaltyAppliedMs = 0;

  if (!allowed && !penaltyActiveBefore) {
    record.violations = normalizePositiveInteger(record.violations, 0) + 1;
    record.lastViolationAt = now;

    if (
      shouldApplyPenalty(record, now) &&
      (
        record.violations >= 3 ||
        burstCount >= 10 ||
        (routeSensitivity === "critical" && record.violations >= 2)
      )
    ) {
      penaltyAppliedMs = applyPenalty(record, now, routeSensitivity);
      penaltyApplied = penaltyAppliedMs > 0;
    }
  }

  await storeRecord(redis, redisKey, record);

  const penaltyActive = safeTimestamp(record.penaltyUntil, 0) > now;
  allowed = record.count <= limit && !penaltyActive;

  const overBy = Math.max(0, record.count - limit);
  const remaining = Math.max(0, limit - record.count);
  const penaltyRemainingMs = penaltyActive
    ? Math.max(0, safeTimestamp(record.penaltyUntil, 0) - now)
    : 0;

  const remainingMs = penaltyActive
    ? penaltyRemainingMs
    : allowed
      ? Math.max(0, windowMs - (now - safeTimestamp(record.start, now)))
      : Math.max(0, windowMs - (now - safeTimestamp(record.start, now)));

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
    containmentAction =
      routeSensitivity === "critical"
        ? "freeze_sensitive_route"
        : "temporary_containment";
  } else if (recommendedAction === "challenge") {
    containmentAction = "step_up_verification";
  } else if (recommendedAction === "throttle") {
    containmentAction = "slow_down_actor";
  }

  const events = {
    blockEvents: recommendedAction === "block" ? 1 : 0,
    challengeEvents: recommendedAction === "challenge" ? 1 : 0,
    throttleEvents: recommendedAction === "throttle" ? 1 : 0,
    hardBlockSignals:
      penaltyActive || (routeSensitivity === "critical" && !allowed) ? 1 : 0,
    burstSignals: burstCount >= 8 ? 1 : 0,
    criticalRouteHits: routeSensitivity === "critical" ? 1 : 0
  };

  return {
    allowed,
    recommendedAction,
    containmentAction,
    remaining,
    remainingMs,
    limit,
    count: normalizePositiveInteger(record.count, 0),
    overBy,
    windowMs,
    resetAt: safeTimestamp(record.start, now) + windowMs,
    penaltyActive,
    penaltyUntil: safeTimestamp(record.penaltyUntil, 0),
    penaltyApplied,
    penaltyAppliedMs,
    violations: normalizePositiveInteger(record.violations, 0),
    routeWeight,
    routeSensitivity,
    burstCount,
    highestCountSeen: normalizePositiveInteger(record.highestCountSeen, 0),
    events
  };
}
