import { redis } from "./_redis.js";

const WINDOW_MS = 10 * 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_REQUEST_HISTORY = 250;

const PENALTY_BASE_MS = 15 * 60 * 1000;
const MAX_PENALTY_MS = 6 * 60 * 60 * 1000;

const BURST_WINDOW_MS = 20 * 1000;
const SUSPICIOUS_HISTORY_DECAY_MS = 30 * 60 * 1000;

const MAX_IP_LENGTH = 100;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_USER_ID_LENGTH = 120;
const MAX_ROUTE_LENGTH = 150;
const MAX_REASON_LENGTH = 120;

function safeString(value, maxLength = 200) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safePositiveInt(value, fallback = 0) {
  const num = Math.floor(safeNumber(value, fallback));
  return num >= 0 ? num : fallback;
}

function normalizeRoute(route) {
  return safeString(route || "unknown-route", MAX_ROUTE_LENGTH).trim().toLowerCase();
}

function normalizeSessionId(sessionId = "") {
  return safeString(sessionId || "no-session", MAX_SESSION_ID_LENGTH).trim();
}

function normalizeUserId(userId = "") {
  return safeString(userId || "anon-user", MAX_USER_ID_LENGTH).trim();
}

function normalizeIp(ip = "") {
  return safeString(ip || "unknown", MAX_IP_LENGTH).trim();
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
    criticalRouteTouches: 0
  };
}

function getRouteClass(route = "") {
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

function getRouteRiskWeight(route) {
  const routeClass = getRouteClass(route);

  if (routeClass === "critical") return 3;
  if (routeClass === "high") return 2;
  return 1;
}

function normalizeRequestItem(item) {
  return {
    at: safeNumber(item?.at, 0),
    route: normalizeRoute(item?.route),
    success: Boolean(item?.success),
    weight: Math.max(1, safePositiveInt(item?.weight, 1)),
    routeClass: safeString(item?.routeClass || "normal", 20)
  };
}

function normalizeRecord(raw, now) {
  const record = raw && typeof raw === "object" ? raw : {};

  return {
    createdAt: safeNumber(record.createdAt, now),
    updatedAt: safeNumber(record.updatedAt, now),
    requests: Array.isArray(record.requests)
      ? record.requests.map(normalizeRequestItem).filter((item) => item.at > 0)
      : [],
    suspiciousEvents: safePositiveInt(record.suspiciousEvents, 0),
    penaltyUntil: safeNumber(record.penaltyUntil, 0),
    penaltyCount: safePositiveInt(record.penaltyCount, 0),
    lastPenaltyReason: safeString(record.lastPenaltyReason, MAX_REASON_LENGTH),
    highestAbuseScore: safePositiveInt(record.highestAbuseScore, 0),
    burstHits: Array.isArray(record.burstHits)
      ? record.burstHits.map((ts) => safeNumber(ts, 0)).filter((ts) => ts > 0)
      : [],
    lastSuspiciousAt: safeNumber(record.lastSuspiciousAt, 0),
    criticalRouteTouches: safePositiveInt(record.criticalRouteTouches, 0)
  };
}

async function getStoredRecord(redisKey, now) {
  try {
    const raw = await redis.get(redisKey);

    if (!raw) {
      return null;
    }

    if (typeof raw === "string") {
      return normalizeRecord(JSON.parse(raw), now);
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

async function storeRecord(redisKey, record) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(STALE_TTL_MS / 1000));
    await redis.set(redisKey, JSON.stringify(record), { ex: ttlSeconds });
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
    .filter((ts) => now - safeNumber(ts, 0) <= BURST_WINDOW_MS)
    .slice(-100);

  return record.burstHits.length;
}

function decaySuspiciousHistory(record, now) {
  if (
    safePositiveInt(record.suspiciousEvents, 0) > 0 &&
    safeNumber(record.lastSuspiciousAt, 0) > 0 &&
    now - safeNumber(record.lastSuspiciousAt, 0) > SUSPICIOUS_HISTORY_DECAY_MS
  ) {
    record.suspiciousEvents = Math.max(0, safePositiveInt(record.suspiciousEvents, 0) - 1);
    record.lastSuspiciousAt = now;
  }
}

function applyPenalty(record, now, reason, abuseScore, routeClass = "normal") {
  const existingPenaltyUntil = safeNumber(record.penaltyUntil);
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
          ? activePenaltyRemaining * 1.5
          : PENALTY_BASE_MS + safePositiveInt(record.penaltyCount) * 10 * 60 * 1000
      ) * classMultiplier
    )
  );

  record.penaltyUntil = now + nextPenaltyMs;
  record.penaltyCount = safePositiveInt(record.penaltyCount) + 1;
  record.lastPenaltyReason = safeString(reason, MAX_REASON_LENGTH);
  record.lastSuspiciousAt = now;

  if (abuseScore >= 85) {
    record.suspiciousEvents = safePositiveInt(record.suspiciousEvents) + 2;
  } else {
    record.suspiciousEvents = safePositiveInt(record.suspiciousEvents) + 1;
  }
}

function getRecommendedAction({
  abuseScore,
  penaltyActive,
  failedRecent,
  totalRequests,
  routeClass,
  burstCount,
  suspiciousEvents
}) {
  if (
    penaltyActive ||
    abuseScore >= 90 ||
    (routeClass === "critical" && abuseScore >= 75)
  ) {
    return "block";
  }

  if (
    abuseScore >= 65 ||
    failedRecent >= 10 ||
    burstCount >= 10 ||
    suspiciousEvents >= 4
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

function getContainmentAction({ recommendedAction, routeClass }) {
  if (recommendedAction === "block") {
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
  ip,
  sessionId,
  userId = ""
} = {}) {
  const now = Date.now();
  const key = getClientKey(ip, sessionId, userId);
  const redisKey = buildAbuseKey(key);

  const record = await getStoredRecord(redisKey, now);

  if (!record) {
    return {
      found: false,
      clientKeyPreview: safeString(key, 24)
    };
  }

  return {
    found: true,
    clientKeyPreview: safeString(key, 24),
    penaltyUntil: safeNumber(record.penaltyUntil, 0),
    penaltyActive: safeNumber(record.penaltyUntil, 0) > now,
    suspiciousEvents: safePositiveInt(record.suspiciousEvents, 0),
    penaltyCount: safePositiveInt(record.penaltyCount, 0),
    highestAbuseScore: safePositiveInt(record.highestAbuseScore, 0),
    updatedAt: safeNumber(record.updatedAt, 0),
    requestCount: Array.isArray(record.requests) ? record.requests.length : 0
  };
}

export async function clearApiAbuse({
  ip,
  sessionId,
  userId = ""
} = {}) {
  const key = getClientKey(ip, sessionId, userId);
  const redisKey = buildAbuseKey(key);

  try {
    await redis.del(redisKey);
    return { ok: true };
  } catch (error) {
    console.error("Redis abuse-protection delete failed:", error);
    return { ok: false };
  }
}

export async function trackApiAbuse({
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

  let record = await getStoredRecord(redisKey, now);

  if (!record) {
    record = createEmptyRecord(now);
  }

  decaySuspiciousHistory(record, now);

  record.updatedAt = now;

  if (routeClass === "critical") {
    record.criticalRouteTouches = safePositiveInt(record.criticalRouteTouches, 0) + 1;
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
    .filter((item) => item && now - safeNumber(item.at) <= WINDOW_MS)
    .slice(-MAX_REQUEST_HISTORY);

  const burstCount = updateBurstHits(record, now);

  const totalRequests = record.requests.length;

  const weightedRequests = record.requests.reduce(
    (sum, item) => sum + Math.max(1, safePositiveInt(item.weight, 1)),
    0
  );

  const failedRecent = record.requests.filter((item) => item.success === false).length;

  const weightedFailures = record.requests
    .filter((item) => item.success === false)
    .reduce((sum, item) => sum + Math.max(1, safePositiveInt(item.weight, 1)), 0);

  const uniqueRoutes = new Set(record.requests.map((item) => item.route)).size;
  const sameRouteBurst = record.requests.filter((item) => item.route === safeRoute).length;

  const highSensitivityTouches = record.requests.filter(
    (item) => item.routeClass === "high" || item.routeClass === "critical"
  ).length;

  const criticalRouteTouchesRecent = record.requests.filter(
    (item) => item.routeClass === "critical"
  ).length;

  const penaltyActive = safeNumber(record.penaltyUntil) > now;

  let abuseScore = 0;
  const reasons = [];

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
  }

  if (sameRouteBurst >= 10) {
    abuseScore += 15;
    reasons.push("same_route_burst");
  }

  if (burstCount >= 8) {
    abuseScore += 15;
    reasons.push("burst_request_pattern");
  }

  if (highSensitivityTouches >= 5) {
    abuseScore += 10;
    reasons.push("high_sensitivity_route_targeting");
  }

  if (criticalRouteTouchesRecent >= 2) {
    abuseScore += 20;
    reasons.push("critical_route_targeting");
  }

  if (safePositiveInt(record.suspiciousEvents, 0) >= 3) {
    abuseScore += 15;
    reasons.push("repeat_suspicious_history");
  }

  if (penaltyActive) {
    abuseScore += 25;
    reasons.push("active_penalty_window");
  }

  abuseScore = Math.min(100, abuseScore);

  record.highestAbuseScore = Math.max(
    safePositiveInt(record.highestAbuseScore, 0),
    safePositiveInt(abuseScore, 0)
  );

  let level = "low";
  if (abuseScore >= 70) {
    level = "high";
  } else if (abuseScore >= 40) {
    level = "medium";
  }

  if (
    abuseScore >= 70 ||
    (failedRecent >= 10 && sameRouteBurst >= 8) ||
    (routeClass === "critical" && abuseScore >= 55)
  ) {
    applyPenalty(
      record,
      now,
      abuseScore >= 85 ? "severe_abuse_pattern" : "sustained_abuse_pattern",
      abuseScore,
      routeClass
    );
  }

  await storeRecord(redisKey, record);

  const finalPenaltyActive = safeNumber(record.penaltyUntil) > now;

  const recommendedAction = getRecommendedAction({
    abuseScore,
    penaltyActive: finalPenaltyActive,
    failedRecent,
    totalRequests,
    routeClass,
    burstCount,
    suspiciousEvents: safePositiveInt(record.suspiciousEvents, 0)
  });

  const containmentAction = getContainmentAction({
    recommendedAction,
    routeClass
  });

  return {
    abuseScore,
    level,
    reasons,
    recommendedAction,
    containmentAction,
    penaltyActive: finalPenaltyActive,
    penaltyUntil: safeNumber(record.penaltyUntil) || 0,
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
      suspiciousEvents: safePositiveInt(record.suspiciousEvents),
      penaltyCount: safePositiveInt(record.penaltyCount),
      highestAbuseScore: safePositiveInt(record.highestAbuseScore, 0),
      routeClass: safeString(routeClass, 20),
      clientKeyPreview: safeString(key, 24)
    }
  };
}
