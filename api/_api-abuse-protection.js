const abuseStore = new Map();

const WINDOW_MS = 10 * 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_REQUEST_HISTORY = 200;
const CLEANUP_INTERVAL_MS = 60 * 1000;

const PENALTY_BASE_MS = 15 * 60 * 1000;
const MAX_PENALTY_MS = 6 * 60 * 60 * 1000;

let lastCleanupAt = 0;

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

function cleanupAbuseStore(force = false) {
  const now = Date.now();

  if (!force && now - lastCleanupAt < CLEANUP_INTERVAL_MS) {
    return;
  }

  lastCleanupAt = now;

  for (const [key, value] of abuseStore.entries()) {
    if (!value || now - safeNumber(value.updatedAt) > STALE_TTL_MS) {
      abuseStore.delete(key);
    }
  }
}

function normalizeRoute(route) {
  return safeString(route || "unknown-route", 150).toLowerCase();
}

function normalizeSessionId(sessionId = "") {
  return safeString(sessionId || "no-session", 120);
}

function getClientKey(ip, sessionId = "") {
  const safeIp = safeString(ip || "unknown", 100);
  const safeSessionId = normalizeSessionId(sessionId);
  return `${safeIp}::${safeSessionId}`;
}

function createEmptyRecord(now) {
  return {
    createdAt: now,
    updatedAt: now,
    requests: [],
    suspiciousEvents: 0,
    penaltyUntil: 0,
    penaltyCount: 0,
    lastPenaltyReason: ""
  };
}

function getRouteRiskWeight(route) {
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

function applyPenalty(record, now, reason, abuseScore) {
  const existingPenaltyUntil = safeNumber(record.penaltyUntil);
  const activePenaltyRemaining = Math.max(0, existingPenaltyUntil - now);

  const nextPenaltyMs = Math.min(
    MAX_PENALTY_MS,
    Math.max(
      PENALTY_BASE_MS,
      activePenaltyRemaining > 0
        ? activePenaltyRemaining * 1.5
        : PENALTY_BASE_MS + safePositiveInt(record.penaltyCount) * 10 * 60 * 1000
    )
  );

  record.penaltyUntil = now + nextPenaltyMs;
  record.penaltyCount = safePositiveInt(record.penaltyCount) + 1;
  record.lastPenaltyReason = safeString(reason, 120);

  if (abuseScore >= 80) {
    record.suspiciousEvents = safePositiveInt(record.suspiciousEvents) + 2;
  } else {
    record.suspiciousEvents = safePositiveInt(record.suspiciousEvents) + 1;
  }
}

function getRecommendedAction({ abuseScore, penaltyActive, failedRecent, totalRequests }) {
  if (penaltyActive || abuseScore >= 85) {
    return "block";
  }

  if (abuseScore >= 65 || failedRecent >= 10) {
    return "challenge";
  }

  if (abuseScore >= 40 || totalRequests >= 20) {
    return "throttle";
  }

  return "allow";
}

export function trackApiAbuse({
  ip,
  sessionId,
  route,
  success = true
} = {}) {
  cleanupAbuseStore();

  const now = Date.now();
  const safeRoute = normalizeRoute(route);
  const routeWeight = getRouteRiskWeight(safeRoute);
  const key = getClientKey(ip, sessionId);

  let record = abuseStore.get(key);

  if (!record) {
    record = createEmptyRecord(now);
  }

  if (!Array.isArray(record.requests)) {
    record.requests = [];
  }

  record.updatedAt = now;

  record.requests.push({
    at: now,
    route: safeRoute,
    success: Boolean(success),
    weight: routeWeight
  });

  record.requests = record.requests
    .filter((item) => item && now - safeNumber(item.at) <= WINDOW_MS)
    .slice(-MAX_REQUEST_HISTORY);

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

  if (record.suspiciousEvents >= 3) {
    abuseScore += 15;
    reasons.push("repeat_suspicious_history");
  }

  if (penaltyActive) {
    abuseScore += 25;
    reasons.push("active_penalty_window");
  }

  abuseScore = Math.min(100, abuseScore);

  let level = "low";
  if (abuseScore >= 70) {
    level = "high";
  } else if (abuseScore >= 40) {
    level = "medium";
  }

  if (abuseScore >= 70 || (failedRecent >= 10 && sameRouteBurst >= 8)) {
    applyPenalty(
      record,
      now,
      abuseScore >= 85 ? "severe_abuse_pattern" : "sustained_abuse_pattern",
      abuseScore
    );
  }

  abuseStore.set(key, record);

  const recommendedAction = getRecommendedAction({
    abuseScore,
    penaltyActive: safeNumber(record.penaltyUntil) > now,
    failedRecent,
    totalRequests
  });

  return {
    abuseScore,
    level,
    reasons,
    recommendedAction,
    penaltyActive: safeNumber(record.penaltyUntil) > now,
    penaltyUntil: safeNumber(record.penaltyUntil) || 0,
    snapshot: {
      totalRequests: safePositiveInt(totalRequests),
      weightedRequests: safePositiveInt(weightedRequests),
      failedRecent: safePositiveInt(failedRecent),
      weightedFailures: safePositiveInt(weightedFailures),
      uniqueRoutes: safePositiveInt(uniqueRoutes),
      sameRouteBurst: safePositiveInt(sameRouteBurst),
      suspiciousEvents: safePositiveInt(record.suspiciousEvents),
      penaltyCount: safePositiveInt(record.penaltyCount),
      clientKeyPreview: safeString(key, 24)
    }
  };
}
