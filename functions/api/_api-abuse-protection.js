import { getRedis } from "./_redis.js";

const WINDOW_MS = 10 * 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_REQUEST_HISTORY = 250;

const PENALTY_BASE_MS = 15 * 60 * 1000;
const MAX_PENALTY_MS = 6 * 60 * 60 * 1000;

const BURST_WINDOW_MS = 20 * 1000;
const SUSPICIOUS_HISTORY_DECAY_MS = 30 * 60 * 1000;
const PENALTY_REAPPLY_GUARD_MS = 60 * 1000;

const MAX_IP_LENGTH = 100;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_USER_ID_LENGTH = 120;
const MAX_ROUTE_LENGTH = 150;
const MAX_REASON_LENGTH = 120;

function stripControlChars(value = "") {
  return String(value ?? "").replace(/[\u0000-\u001F\u007F]/g, "");
}

function safeString(value, maxLength = 200) {
  return stripControlChars(value).trim().slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safePositiveInt(value, fallback = 0, max = 1_000_000) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num) || num < 0) return fallback;
  return Math.min(num, max);
}

function safeTimestamp(value, fallback = 0) {
  return safePositiveInt(value, fallback, Date.now() + 60_000);
}

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function sanitizeKeyPart(value = "", maxLength = 120, fallback = "") {
  const cleaned = safeString(value, maxLength).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  return cleaned || fallback;
}

function normalizeRoute(route = "") {
  const raw = safeString(route || "unknown-route", MAX_ROUTE_LENGTH * 2);

  if (!raw) return "unknown-route";

  const withoutQuery = raw.split("?")[0].split("#")[0];

  const cleaned = withoutQuery
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .trim()
    .toLowerCase()
    .slice(0, MAX_ROUTE_LENGTH);

  return cleaned || "unknown-route";
}

function normalizeSessionId(sessionId = "") {
  return sanitizeKeyPart(
    sessionId || "no-session",
    MAX_SESSION_ID_LENGTH,
    "no-session"
  );
}

function normalizeUserId(userId = "") {
  return sanitizeKeyPart(
    userId || "anon-user",
    MAX_USER_ID_LENGTH,
    "anon-user"
  );
}

function normalizeIp(ip = "") {
  let value = safeString(ip || "unknown", MAX_IP_LENGTH);

  if (!value) return "unknown";

  if (value.startsWith("::ffff:")) {
    value = value.slice(7);
  }

  value = value.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, MAX_IP_LENGTH);

  return value || "unknown";
}

function getClientKey(ip, sessionId = "", userId = "") {
  const safeIp = normalizeIp(ip);
  const safeSessionId = normalizeSessionId(sessionId);
  const safeUserId = normalizeUserId(userId);
  return `${safeIp}::${safeSessionId}::${safeUserId}`;
}

function buildAbuseKey(clientKey) {
  return `abuse:${safeString(clientKey, 280)}`;
}

function createEmptyRecord(now) {
  return {
    createdAt: now,
    updatedAt: now,
    requests: [],
    suspiciousEvents: 0,
    penaltyUntil: 0,
    penaltyCount: 0,
    lastPenaltyReason: "",
    highestAbuseScore: 0,
    burstHits: [],
    lastSuspiciousAt: 0,
    criticalRouteTouches: 0,
    highRouteTouches: 0,
    uniqueCriticalRoutes: [],
    lastPenaltyAppliedAt: 0
  };
}

function getRouteClass(route = "") {
  const normalized = normalizeRoute(route);

  if (
    normalized.includes("admin") ||
    normalized.includes("developer") ||
    normalized.includes("role") ||
    normalized.includes("claims") ||
    normalized.includes("security") ||
    normalized.includes("metrics") ||
    normalized.includes("containment")
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

function getRouteRiskWeight(route = "") {
  const routeClass = getRouteClass(route);

  if (routeClass === "critical") return 3;
  if (routeClass === "high") return 2;
  return 1;
}

function normalizeRequestItem(item = {}) {
  const routeClass = safeString(item?.routeClass || "normal", 20).toLowerCase();

  return {
    at: safeTimestamp(item?.at, 0),
    route: normalizeRoute(item?.route),
    success: item?.success === true,
    weight: Math.max(1, safePositiveInt(item?.weight, 1, 10)),
    routeClass:
      routeClass === "critical" || routeClass === "high"
        ? routeClass
        : "normal"
  };
}

function normalizeRecord(raw, now) {
  const record = raw && typeof raw === "object" ? raw : {};

  return {
    createdAt: safeTimestamp(record.createdAt, now),
    updatedAt: safeTimestamp(record.updatedAt, now),
    requests: Array.isArray(record.requests)
      ? record.requests
          .map(normalizeRequestItem)
          .filter((item) => item.at > 0 && now - item.at <= STALE_TTL_MS)
          .slice(-MAX_REQUEST_HISTORY)
      : [],
    suspiciousEvents: safePositiveInt(record.suspiciousEvents, 0),
    penaltyUntil: safeTimestamp(record.penaltyUntil, 0),
    penaltyCount: safePositiveInt(record.penaltyCount, 0),
    lastPenaltyReason: safeString(record.lastPenaltyReason, MAX_REASON_LENGTH),
    highestAbuseScore: safePositiveInt(record.highestAbuseScore, 0, 100),
    burstHits: Array.isArray(record.burstHits)
      ? record.burstHits
          .map((ts) => safeTimestamp(ts, 0))
          .filter((ts) => ts > 0 && now - ts <= BURST_WINDOW_MS)
          .slice(-100)
      : [],
    lastSuspiciousAt: safeTimestamp(record.lastSuspiciousAt, 0),
    criticalRouteTouches: safePositiveInt(record.criticalRouteTouches, 0),
    highRouteTouches: safePositiveInt(record.highRouteTouches, 0),
    uniqueCriticalRoutes: Array.isArray(record.uniqueCriticalRoutes)
      ? record.uniqueCriticalRoutes.map((route) => normalizeRoute(route)).slice(-25)
      : [],
    lastPenaltyAppliedAt: safeTimestamp(record.lastPenaltyAppliedAt, 0)
  };
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
    console.error("Redis abuse-protection read failed:", error);
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
    console.error("Redis abuse-protection write failed:", error);
    return false;
  }
}

function updateBurstHits(record, now) {
  if (!Array.isArray(record.burstHits)) {
    record.burstHits = [];
  }

  record.burstHits.push(now);
  record.burstHits = record.burstHits
    .filter((ts) => now - safeTimestamp(ts, 0) <= BURST_WINDOW_MS)
    .slice(-100);

  return record.burstHits.length;
}

function decaySuspiciousHistory(record, now) {
  const suspiciousEvents = safePositiveInt(record.suspiciousEvents, 0);
  const lastSuspiciousAt = safeTimestamp(record.lastSuspiciousAt, 0);

  if (
    suspiciousEvents > 0 &&
    lastSuspiciousAt > 0 &&
    now - lastSuspiciousAt > SUSPICIOUS_HISTORY_DECAY_MS
  ) {
    const decaySteps = Math.floor(
      (now - lastSuspiciousAt) / SUSPICIOUS_HISTORY_DECAY_MS
    );

    record.suspiciousEvents = Math.max(
      0,
      suspiciousEvents - Math.max(1, decaySteps)
    );

    record.lastSuspiciousAt = now;
  }
}

function shouldApplyPenalty(record, now) {
  const lastPenaltyAppliedAt = safeTimestamp(record.lastPenaltyAppliedAt, 0);
  return now - lastPenaltyAppliedAt >= PENALTY_REAPPLY_GUARD_MS;
}

function applyPenalty(record, now, reason, abuseScore, routeClass = "normal") {
  const existingPenaltyUntil = safeTimestamp(record.penaltyUntil, 0);
  const activePenaltyRemaining = Math.max(0, existingPenaltyUntil - now);

  let classMultiplier = 1;
  if (routeClass === "critical") classMultiplier = 1.8;
  else if (routeClass === "high") classMultiplier = 1.3;

  const nextPenaltyMs = Math.min(
    MAX_PENALTY_MS,
    Math.floor(
      Math.max(
        PENALTY_BASE_MS,
        activePenaltyRemaining > 0
          ? activePenaltyRemaining * 1.35
          : PENALTY_BASE_MS +
              safePositiveInt(record.penaltyCount) * 10 * 60 * 1000
      ) * classMultiplier
    )
  );

  record.penaltyUntil = now + nextPenaltyMs;
  record.penaltyCount = safePositiveInt(record.penaltyCount) + 1;
  record.lastPenaltyReason = safeString(reason, MAX_REASON_LENGTH);
  record.lastSuspiciousAt = now;
  record.suspiciousEvents =
    safePositiveInt(record.suspiciousEvents) + (abuseScore >= 85 ? 2 : 1);
  record.lastPenaltyAppliedAt = now;
}

function getRecommendedAction({
  abuseScore,
  penaltyActive,
  failedRecent,
  totalRequests,
  routeClass,
  burstCount,
  suspiciousEvents,
  coordinatedProbe,
  breachLikePattern
}) {
  if (
    penaltyActive ||
    abuseScore >= 90 ||
    breachLikePattern ||
    (routeClass === "critical" && abuseScore >= 75)
  ) {
    return "block";
  }

  if (
    abuseScore >= 65 ||
    failedRecent >= 10 ||
    burstCount >= 10 ||
    suspiciousEvents >= 4 ||
    coordinatedProbe
  ) {
    return "challenge";
  }

  if (
    abuseScore >= 40 ||
    totalRequests >= 20 ||
    burstCount >= 6
  ) {
    return "throttle";
  }

  return "allow";
}

function getContainmentAction({
  recommendedAction,
  routeClass,
  breachLikePattern
}) {
  if (recommendedAction === "block") {
    if (breachLikePattern) return "critical_containment";
    return routeClass === "critical"
      ? "freeze_sensitive_route"
      : "temporary_containment";
  }

  if (recommendedAction === "challenge") {
    return "step_up_verification";
  }

  if (recommendedAction === "throttle") {
    return "slow_down_actor";
  }

  return "none";
}

export async function getApiAbuseSnapshot({
  env = {},
  ip,
  sessionId,
  userId = ""
} = {}) {
  const now = Date.now();
  const key = getClientKey(ip, sessionId, userId);
  const redisKey = buildAbuseKey(key);
  const redis = getRedis(env);

  const record = await getStoredRecord(redis, redisKey, now);

  if (!record) {
    return {
      found: false,
      clientKeyPreview: safeString(key, 24)
    };
  }

  return {
    found: true,
    clientKeyPreview: safeString(key, 24),
    penaltyUntil: safeTimestamp(record.penaltyUntil, 0),
    penaltyActive: safeTimestamp(record.penaltyUntil, 0) > now,
    suspiciousEvents: safePositiveInt(record.suspiciousEvents, 0),
    penaltyCount: safePositiveInt(record.penaltyCount, 0),
    highestAbuseScore: safePositiveInt(record.highestAbuseScore, 0, 100),
    updatedAt: safeTimestamp(record.updatedAt, 0),
    requestCount: Array.isArray(record.requests) ? record.requests.length : 0,
    lastPenaltyReason: safeString(record.lastPenaltyReason, MAX_REASON_LENGTH)
  };
}

export async function clearApiAbuse({
  env = {},
  ip,
  sessionId,
  userId = ""
} = {}) {
  const key = getClientKey(ip, sessionId, userId);
  const redisKey = buildAbuseKey(key);
  const redis = getRedis(env);

  try {
    await redis.del(redisKey);
    return { ok: true };
  } catch (error) {
    console.error("Redis abuse-protection delete failed:", error);
    return { ok: false };
  }
}

export async function trackApiAbuse({
  env = {},
  ip,
  sessionId,
  userId = "",
  route,
  success = true
} = {}) {
  const now = Date.now();
  const safeRoute = normalizeRoute(route);
  const routeClass = getRouteClass(safeRoute);
  const routeWeight = getRouteRiskWeight(safeRoute);
  const key = getClientKey(ip, sessionId, userId);
  const redisKey = buildAbuseKey(key);
  const redis = getRedis(env);

  let record = await getStoredRecord(redis, redisKey, now);
  if (!record) {
    record = createEmptyRecord(now);
  }

  decaySuspiciousHistory(record, now);
  record.updatedAt = now;

  if (routeClass === "critical") {
    record.criticalRouteTouches = safePositiveInt(record.criticalRouteTouches, 0) + 1;
    record.uniqueCriticalRoutes = Array.from(
      new Set([...(record.uniqueCriticalRoutes || []), safeRoute])
    ).slice(-25);
  } else if (routeClass === "high") {
    record.highRouteTouches = safePositiveInt(record.highRouteTouches, 0) + 1;
  }

  if (!Array.isArray(record.requests)) {
    record.requests = [];
  }

  record.requests.push({
    at: now,
    route: safeRoute,
    success: Boolean(success),
    weight: routeWeight,
    routeClass
  });

  record.requests = record.requests
    .filter((item) => item && now - safeTimestamp(item.at, 0) <= WINDOW_MS)
    .slice(-MAX_REQUEST_HISTORY);

  const burstCount = updateBurstHits(record, now);
  const totalRequests = record.requests.length;

  const weightedRequests = record.requests.reduce(
    (sum, item) => sum + Math.max(1, safePositiveInt(item.weight, 1, 10)),
    0
  );

  const failedRecent = record.requests.filter((item) => item.success === false).length;

  const weightedFailures = record.requests
    .filter((item) => item.success === false)
    .reduce(
      (sum, item) => sum + Math.max(1, safePositiveInt(item.weight, 1, 10)),
      0
    );

  const uniqueRoutes = new Set(record.requests.map((item) => item.route)).size;
  const sameRouteBurst = record.requests.filter((item) => item.route === safeRoute).length;

  const highSensitivityTouches = record.requests.filter(
    (item) => item.routeClass === "high" || item.routeClass === "critical"
  ).length;

  const criticalRouteTouchesRecent = record.requests.filter(
    (item) => item.routeClass === "critical"
  ).length;

  const uniqueCriticalRoutesRecent = new Set(
    record.requests
      .filter((item) => item.routeClass === "critical")
      .map((item) => item.route)
  ).size;

  const penaltyActive = safeTimestamp(record.penaltyUntil, 0) > now;

  let abuseScore = 0;
  const reasons = [];
  const events = {
    burstEvents: 0,
    probeEvents: 0,
    criticalRouteHits: 0,
    breachSignals: 0,
    hardBlockSignals: 0,
    endpointSpread: 0
  };

  if (weightedRequests >= 20) {
    abuseScore += 20;
    reasons.push("high_total_requests");
  }

  if (weightedRequests >= 40) {
    abuseScore += 20;
    reasons.push("extreme_request_volume");
  }

  if (weightedFailures >= 6) {
    abuseScore += 20;
    reasons.push("repeated_failures");
  }

  if (weightedFailures >= 12) {
    abuseScore += 20;
    reasons.push("heavy_failed_requests");
  }

  if (uniqueRoutes >= 4) {
    abuseScore += 15;
    reasons.push("multi_endpoint_probing");
    events.probeEvents += 1;
    events.endpointSpread = uniqueRoutes;
  }

  if (sameRouteBurst >= 10) {
    abuseScore += 15;
    reasons.push("same_route_burst");
    events.burstEvents += 1;
  }

  if (burstCount >= 8) {
    abuseScore += 15;
    reasons.push("burst_request_pattern");
    events.burstEvents += 1;
  }

  if (highSensitivityTouches >= 5) {
    abuseScore += 10;
    reasons.push("high_sensitivity_route_targeting");
  }

  if (criticalRouteTouchesRecent >= 2) {
    abuseScore += 20;
    reasons.push("critical_route_targeting");
    events.criticalRouteHits = criticalRouteTouchesRecent;
  }

  if (uniqueCriticalRoutesRecent >= 2) {
    abuseScore += 15;
    reasons.push("critical_endpoint_spread");
    events.probeEvents += 1;
  }

  if (safePositiveInt(record.suspiciousEvents, 0) >= 3) {
    abuseScore += 15;
    reasons.push("repeat_suspicious_history");
  }

  if (penaltyActive) {
    abuseScore += 25;
    reasons.push("active_penalty_window");
    events.hardBlockSignals += 1;
  }

  const coordinatedProbe =
    uniqueRoutes >= 5 ||
    uniqueCriticalRoutesRecent >= 2 ||
    (criticalRouteTouchesRecent >= 3 && highSensitivityTouches >= 5);

  const breachLikePattern =
    (routeClass === "critical" && weightedRequests >= 20) ||
    uniqueCriticalRoutesRecent >= 3 ||
    (criticalRouteTouchesRecent >= 4 && weightedFailures >= 6);

  if (coordinatedProbe) {
    abuseScore += 10;
    reasons.push("coordinated_route_probe");
    events.probeEvents += 1;
  }

  if (breachLikePattern) {
    abuseScore += 20;
    reasons.push("possible_sensitive_extraction_pattern");
    events.breachSignals += 1;
    events.hardBlockSignals += 1;
  }

  abuseScore = Math.min(100, abuseScore);

  record.highestAbuseScore = Math.max(
    safePositiveInt(record.highestAbuseScore, 0, 100),
    safePositiveInt(abuseScore, 0, 100)
  );

  let level = "low";
  if (abuseScore >= 70) {
    level = "high";
  } else if (abuseScore >= 40) {
    level = "medium";
  }

  const severePattern =
    abuseScore >= 70 ||
    breachLikePattern ||
    (failedRecent >= 10 && sameRouteBurst >= 8) ||
    (routeClass === "critical" && abuseScore >= 55);

  if (severePattern && shouldApplyPenalty(record, now)) {
    applyPenalty(
      record,
      now,
      breachLikePattern
        ? "possible_sensitive_extraction_pattern"
        : abuseScore >= 85
          ? "severe_abuse_pattern"
          : "sustained_abuse_pattern",
      abuseScore,
      routeClass
    );
  }

  await storeRecord(redis, redisKey, record);

  const finalPenaltyActive = safeTimestamp(record.penaltyUntil, 0) > now;

  const recommendedAction = getRecommendedAction({
    abuseScore,
    penaltyActive: finalPenaltyActive,
    failedRecent,
    totalRequests,
    routeClass,
    burstCount,
    suspiciousEvents: safePositiveInt(record.suspiciousEvents, 0),
    coordinatedProbe,
    breachLikePattern
  });

  const containmentAction = getContainmentAction({
    recommendedAction,
    routeClass,
    breachLikePattern
  });

  return {
    abuseScore,
    level,
    reasons,
    recommendedAction,
    containmentAction,
    penaltyActive: finalPenaltyActive,
    penaltyUntil: safeTimestamp(record.penaltyUntil, 0),
    events,
    snapshot: {
      totalRequests: safePositiveInt(totalRequests),
      weightedRequests: safePositiveInt(weightedRequests),
      failedRecent: safePositiveInt(failedRecent),
      weightedFailures: safePositiveInt(weightedFailures),
      uniqueRoutes: safePositiveInt(uniqueRoutes),
      sameRouteBurst: safePositiveInt(sameRouteBurst),
      burstCount: safePositiveInt(burstCount),
      highSensitivityTouches: safePositiveInt(highSensitivityTouches),
      criticalRouteTouchesRecent: safePositiveInt(criticalRouteTouchesRecent),
      uniqueCriticalRoutesRecent: safePositiveInt(uniqueCriticalRoutesRecent),
      suspiciousEvents: safePositiveInt(record.suspiciousEvents),
      penaltyCount: safePositiveInt(record.penaltyCount),
      highestAbuseScore: safePositiveInt(record.highestAbuseScore, 0, 100),
      routeClass: safeString(routeClass, 20),
      clientKeyPreview: safeString(key, 24),
      lastPenaltyReason: safeString(record.lastPenaltyReason, MAX_REASON_LENGTH),
      coordinatedProbe,
      breachLikePattern
    }
  };
}
