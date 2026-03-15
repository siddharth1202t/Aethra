const abuseStore = new Map();

const WINDOW_MS = 10 * 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;

function safeString(value, maxLength = 200) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function cleanupAbuseStore() {
  const now = Date.now();

  for (const [key, value] of abuseStore.entries()) {
    if (!value || now - safeNumber(value.updatedAt) > STALE_TTL_MS) {
      abuseStore.delete(key);
    }
  }
}

function getClientKey(ip, sessionId = "") {
  const safeIp = safeString(ip || "unknown", 100);
  const safeSessionId = safeString(sessionId || "no-session", 120);
  return `${safeIp}::${safeSessionId}`;
}

function createEmptyRecord(now) {
  return {
    createdAt: now,
    updatedAt: now,
    requests: []
  };
}

export function trackApiAbuse({
  ip,
  sessionId,
  route,
  success = true
} = {}) {
  cleanupAbuseStore();

  const now = Date.now();
  const safeRoute = safeString(route || "unknown-route", 150);
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
    success: Boolean(success)
  });

  record.requests = record.requests.filter((item) => {
    return item && now - safeNumber(item.at) <= WINDOW_MS;
  });

  abuseStore.set(key, record);

  const totalRequests = record.requests.length;
  const failedRecent = record.requests.filter((item) => item.success === false).length;
  const uniqueRoutes = new Set(record.requests.map((item) => item.route)).size;
  const sameRouteBurst = record.requests.filter((item) => item.route === safeRoute).length;

  let abuseScore = 0;
  const reasons = [];

  if (totalRequests >= 20) {
    abuseScore += 20;
    reasons.push("high_total_requests");
  }

  if (totalRequests >= 40) {
    abuseScore += 25;
    reasons.push("extreme_request_volume");
  }

  if (failedRecent >= 5) {
    abuseScore += 20;
    reasons.push("repeated_failures");
  }

  if (failedRecent >= 10) {
    abuseScore += 25;
    reasons.push("heavy_failed_requests");
  }

  if (uniqueRoutes >= 4) {
    abuseScore += 15;
    reasons.push("multi_endpoint_probing");
  }

  if (sameRouteBurst >= 10) {
    abuseScore += 20;
    reasons.push("same_route_burst");
  }

  let level = "low";
  if (abuseScore >= 70) {
    level = "high";
  } else if (abuseScore >= 40) {
    level = "medium";
  }

  return {
    abuseScore,
    level,
    reasons,
    snapshot: {
      totalRequests,
      failedRecent,
      uniqueRoutes,
      sameRouteBurst,
      clientKey: key
    }
  };
}
