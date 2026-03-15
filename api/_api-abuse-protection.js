const abuseStore = new Map();

const WINDOW_MS = 10 * 60 * 1000;
const STALE_TTL_MS = 24 * 60 * 60 * 1000;

function cleanupAbuseStore() {
  const now = Date.now();

  for (const [key, value] of abuseStore.entries()) {
    if (!value || now - value.updatedAt > STALE_TTL_MS) {
      abuseStore.delete(key);
    }
  }
}

function getClientKey(ip, sessionId = "") {
  return `${ip || "unknown"}::${sessionId || "no-session"}`;
}

export function trackApiAbuse({
  ip,
  sessionId,
  route,
  success = true
}) {
  cleanupAbuseStore();

  const now = Date.now();
  const key = getClientKey(ip, sessionId);

  let record = abuseStore.get(key);
  if (!record) {
    record = {
      createdAt: now,
      updatedAt: now,
      requests: [],
      failedCount: 0,
      routeHits: {}
    };
  }

  record.updatedAt = now;
  record.requests.push({
    at: now,
    route,
    success
  });

  record.requests = record.requests.filter(item => now - item.at <= WINDOW_MS);

  if (!success) {
    record.failedCount += 1;
  }

  record.routeHits[route] = (record.routeHits[route] || 0) + 1;

  abuseStore.set(key, record);

  const totalRequests = record.requests.length;
  const failedRecent = record.requests.filter(item => !item.success).length;
  const uniqueRoutes = new Set(record.requests.map(item => item.route)).size;
  const sameRouteBurst = record.requests.filter(item => item.route === route).length;

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
  if (abuseScore >= 70) level = "high";
  else if (abuseScore >= 40) level = "medium";

  return {
    abuseScore,
    level,
    reasons,
    snapshot: {
      totalRequests,
      failedRecent,
      uniqueRoutes,
      sameRouteBurst
    }
  };
}
