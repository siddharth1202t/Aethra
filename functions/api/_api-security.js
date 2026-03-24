import { checkApiRateLimit } from "./_rate-limit.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";
import { analyzeBotBehavior } from "./_bot-detection.js";

const securityStateStore = {
  mode: "normal",
  updatedAt: Date.now(),
  lastEscalationReason: "",
  suspiciousEvents: []
};

const actorMemoryStore = new Map();

const SECURITY_MODE_TTL_MS = 15 * 60 * 1000;
const SUSPICIOUS_EVENT_WINDOW_MS = 10 * 60 * 1000;
const MAX_SUSPICIOUS_EVENTS = 200;

const ACTOR_MEMORY_TTL_MS = 24 * 60 * 60 * 1000;
const ACTOR_CLEANUP_INTERVAL_MS = 60 * 1000;
let lastActorCleanupAt = 0;

const ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "HEAD"
]);

export function safeString(value, maxLength = 300) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

export function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

export function safePositiveInt(value, fallback = 0, max = 1_000_000) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num) || num < 0) return fallback;
  return Math.min(num, max);
}

export function safeBoolean(value) {
  return Boolean(value);
}

export function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function getHeaderValue(headers, name) {
  if (!headers) return "";

  const target = String(name).toLowerCase();

  if (typeof headers.get === "function") {
    return safeString(headers.get(name) || headers.get(target) || "", 1000);
  }

  if (isPlainObject(headers)) {
    for (const [key, value] of Object.entries(headers)) {
      if (String(key).toLowerCase() === target) {
        return safeString(value, 1000);
      }
    }
  }

  return "";
}

function normalizeIp(value = "") {
  let ip = safeString(value || "unknown", 100);

  if (!ip) return "unknown";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return ip || "unknown";
}

export function getClientIp(req) {
  const headers = req?.headers;

  const cfIp = getHeaderValue(headers, "cf-connecting-ip");
  if (cfIp) {
    return normalizeIp(cfIp);
  }

  const realIp = getHeaderValue(headers, "x-real-ip");
  if (realIp) {
    return normalizeIp(realIp);
  }

  const forwarded = getHeaderValue(headers, "x-forwarded-for");
  if (forwarded) {
    return normalizeIp(forwarded.split(",")[0]?.trim());
  }

  return normalizeIp(req?.ip || req?.socket?.remoteAddress || "unknown");
}

export function normalizeOrigin(origin = "") {
  const raw = safeString(origin, 200);

  if (!raw) return "";

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

function normalizeMethod(method = "") {
  const normalized = safeString(method || "", 20).toUpperCase();
  if (!normalized) return "INVALID";
  return ALLOWED_METHODS.has(normalized) ? normalized : "INVALID";
}

function normalizeContentType(value = "") {
  return safeString(value || "", 120).toLowerCase();
}

export function isAllowedOrigin(origin, allowedOrigins = []) {
  const normalizedOrigin = normalizeOrigin(origin);

  if (!normalizedOrigin) {
    return false;
  }

  if (allowedOrigins instanceof Set) {
    return allowedOrigins.has(normalizedOrigin);
  }

  if (Array.isArray(allowedOrigins)) {
    return allowedOrigins.includes(normalizedOrigin);
  }

  return false;
}

export function sanitizeBody(body, maxKeys = 20) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return {};
  }

  const entries = Object.entries(body).slice(0, maxKeys);
  const output = {};

  for (const [key, value] of entries) {
    output[safeString(key, 50)] = value;
  }

  return output;
}

export function sanitizeMetadata(
  value,
  depth = 0,
  maxDepth = 4,
  maxKeys = 20,
  maxArrayItems = 20
) {
  if (depth > maxDepth) {
    return "[max-depth]";
  }

  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value === "string") {
    return safeString(value, 1000);
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, maxArrayItems)
      .map((item) =>
        sanitizeMetadata(item, depth + 1, maxDepth, maxKeys, maxArrayItems)
      );
  }

  if (isPlainObject(value)) {
    const output = {};
    const entries = Object.entries(value).slice(0, maxKeys);

    for (const [key, val] of entries) {
      output[safeString(key, 100)] = sanitizeMetadata(
        val,
        depth + 1,
        maxDepth,
        maxKeys,
        maxArrayItems
      );
    }

    return output;
  }

  return safeString(value, 500);
}

export function buildBlockedResponse(message, extra = {}) {
  return {
    success: false,
    message: safeString(message || "Request blocked.", 300),
    ...extra
  };
}

export function buildSuccessResponse(extra = {}) {
  return {
    success: true,
    ...extra
  };
}

export function buildMethodNotAllowedResponse() {
  return {
    success: false,
    message: "Method not allowed."
  };
}

function normalizeRoute(route = "") {
  const raw = safeString(route || "unknown-route", 300);

  if (!raw) return "unknown-route";

  const withoutQuery = raw.split("?")[0].split("#")[0];

  const cleaned = withoutQuery
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, 150);

  return cleaned || "unknown-route";
}

function getRouteSensitivity(route = "") {
  const normalized = normalizeRoute(route);

  if (
    normalized.includes("admin") ||
    normalized.includes("developer") ||
    normalized.includes("role") ||
    normalized.includes("claims") ||
    normalized.includes("containment") ||
    normalized.includes("security") ||
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

function getRouteRiskWeight(route = "") {
  const sensitivity = getRouteSensitivity(route);

  if (sensitivity === "critical") return 3;
  if (sensitivity === "high") return 2;
  return 1;
}

function cleanupActorMemory(force = false) {
  const now = Date.now();

  if (!force && now - lastActorCleanupAt < ACTOR_CLEANUP_INTERVAL_MS) {
    return;
  }

  lastActorCleanupAt = now;

  for (const [key, record] of actorMemoryStore.entries()) {
    if (!record || now - safeNumber(record.updatedAt, 0) > ACTOR_MEMORY_TTL_MS) {
      actorMemoryStore.delete(key);
    }
  }
}

function getActorKey(ip, sessionId = "") {
  const normalizedSession = safeString(sessionId || "no-session", 120).replace(
    /[^a-zA-Z0-9._:@/-]/g,
    ""
  );

  return `${normalizeIp(ip || "unknown")}::${normalizedSession || "no-session"}`;
}

function getActorRiskBonus(actorMemory = null) {
  if (!actorMemory || typeof actorMemory !== "object") {
    return 0;
  }

  let bonus = 0;

  const suspiciousCount = safePositiveInt(actorMemory.suspiciousCount, 0, 1000);
  const blockedCount = safePositiveInt(actorMemory.blockedCount, 0, 1000);
  const challengedCount = safePositiveInt(actorMemory.challengedCount, 0, 1000);
  const highestRisk = safePositiveInt(actorMemory.highestRisk, 0, 100);

  bonus += Math.min(20, suspiciousCount * 2);
  bonus += Math.min(20, blockedCount * 5);
  bonus += Math.min(10, challengedCount * 2);

  if (highestRisk >= 90) {
    bonus += 20;
  } else if (highestRisk >= 75) {
    bonus += 12;
  } else if (highestRisk >= 60) {
    bonus += 6;
  }

  return Math.min(40, bonus);
}

function recordSuspiciousEvent({
  route = "unknown-route",
  ip = "unknown",
  finalAction = "allow",
  combinedRisk = 0,
  reason = "",
  exploitSignals = 0,
  breachSignals = 0
} = {}) {
  const now = Date.now();

  securityStateStore.suspiciousEvents.push({
    at: now,
    route: normalizeRoute(route),
    ip: normalizeIp(ip),
    finalAction: safeString(finalAction, 30).toLowerCase(),
    combinedRisk: safePositiveInt(combinedRisk, 0, 100),
    reason: safeString(reason, 120),
    exploitSignals: safePositiveInt(exploitSignals, 0, 20),
    breachSignals: safePositiveInt(breachSignals, 0, 20)
  });

  securityStateStore.suspiciousEvents = securityStateStore.suspiciousEvents
    .filter((item) => item && now - safeNumber(item.at, 0) <= SUSPICIOUS_EVENT_WINDOW_MS)
    .slice(-MAX_SUSPICIOUS_EVENTS);
}

function updateSecurityMode() {
  const now = Date.now();

  if (now - safeNumber(securityStateStore.updatedAt, 0) > SECURITY_MODE_TTL_MS) {
    securityStateStore.mode = "normal";
    securityStateStore.lastEscalationReason = "ttl_reset";
  }

  securityStateStore.suspiciousEvents = securityStateStore.suspiciousEvents.filter(
    (item) => item && now - safeNumber(item.at, 0) <= SUSPICIOUS_EVENT_WINDOW_MS
  );

  const recentBlocks = securityStateStore.suspiciousEvents.filter(
    (item) => item.finalAction === "block"
  ).length;

  const recentChallenges = securityStateStore.suspiciousEvents.filter(
    (item) => item.finalAction === "challenge"
  ).length;

  const recentHighRisk = securityStateStore.suspiciousEvents.filter(
    (item) => safePositiveInt(item.combinedRisk, 0, 100) >= 70
  ).length;

  const recentExploitSignals = securityStateStore.suspiciousEvents.reduce(
    (sum, item) => sum + safePositiveInt(item.exploitSignals, 0, 20),
    0
  );

  const recentBreachSignals = securityStateStore.suspiciousEvents.reduce(
    (sum, item) => sum + safePositiveInt(item.breachSignals, 0, 20),
    0
  );

  let mode = "normal";
  let reason = "stable_activity";

  if (
    recentBreachSignals >= 2 ||
    recentExploitSignals >= 3 ||
    recentBlocks >= 10 ||
    recentHighRisk >= 20
  ) {
    mode = "lockdown";
    reason = "critical_attack_pressure";
  } else if (
    recentBlocks >= 4 ||
    recentChallenges >= 12 ||
    recentHighRisk >= 10 ||
    recentExploitSignals >= 1
  ) {
    mode = "attack";
    reason = "elevated_suspicious_activity";
  } else if (recentChallenges >= 5 || recentHighRisk >= 5) {
    mode = "elevated";
    reason = "moderate_suspicious_activity";
  }

  securityStateStore.mode = mode;
  securityStateStore.updatedAt = now;
  securityStateStore.lastEscalationReason = reason;

  return {
    mode,
    reason,
    updatedAt: securityStateStore.updatedAt
  };
}

function getSecurityModeRiskBonus(mode = "normal") {
  if (mode === "lockdown") return 25;
  if (mode === "attack") return 15;
  if (mode === "elevated") return 8;
  return 0;
}

function getAdaptiveLimitMultiplier(mode = "normal", route = "") {
  const sensitivity = getRouteSensitivity(route);

  if (mode === "lockdown") {
    if (sensitivity === "critical") return 0.2;
    if (sensitivity === "high") return 0.35;
    return 0.5;
  }

  if (mode === "attack") {
    if (sensitivity === "critical") return 0.35;
    if (sensitivity === "high") return 0.5;
    return 0.7;
  }

  if (mode === "elevated") {
    if (sensitivity === "critical") return 0.5;
    if (sensitivity === "high") return 0.7;
    return 0.85;
  }

  return 1;
}

function getOrCreateActorMemory(ip, sessionId = "") {
  cleanupActorMemory();

  const key = getActorKey(ip, sessionId);
  const now = Date.now();

  let record = actorMemoryStore.get(key);

  if (!record) {
    record = {
      createdAt: now,
      updatedAt: now,
      suspiciousCount: 0,
      blockedCount: 0,
      challengedCount: 0,
      exploitFlags: 0,
      breachFlags: 0,
      highestRisk: 0,
      lastRoute: "unknown-route",
      lastAction: "allow"
    };
  }

  return { key, record };
}

function updateActorMemory({
  ip,
  sessionId = "",
  route = "",
  combinedRisk = 0,
  finalAction = "allow",
  exploitSignals = 0,
  breachSignals = 0
} = {}) {
  const now = Date.now();
  const { key, record } = getOrCreateActorMemory(ip, sessionId);

  record.updatedAt = now;
  record.highestRisk = Math.max(
    safePositiveInt(record.highestRisk, 0, 100),
    safePositiveInt(combinedRisk, 0, 100)
  );
  record.lastRoute = normalizeRoute(route);
  record.lastAction = safeString(finalAction, 30).toLowerCase();
  record.exploitFlags = safePositiveInt(record.exploitFlags, 0) + safePositiveInt(exploitSignals, 0, 5);
  record.breachFlags = safePositiveInt(record.breachFlags, 0) + safePositiveInt(breachSignals, 0, 5);

  if (finalAction === "block") {
    record.blockedCount = safePositiveInt(record.blockedCount, 0) + 1;
    record.suspiciousCount = safePositiveInt(record.suspiciousCount, 0) + 2;
  } else if (finalAction === "challenge") {
    record.challengedCount = safePositiveInt(record.challengedCount, 0) + 1;
    record.suspiciousCount = safePositiveInt(record.suspiciousCount, 0) + 1;
  } else if (combinedRisk >= 60) {
    record.suspiciousCount = safePositiveInt(record.suspiciousCount, 0) + 1;
  }

  actorMemoryStore.set(key, record);

  return {
    actorKey: key,
    actorMemory: {
      suspiciousCount: safePositiveInt(record.suspiciousCount, 0),
      blockedCount: safePositiveInt(record.blockedCount, 0),
      challengedCount: safePositiveInt(record.challengedCount, 0),
      exploitFlags: safePositiveInt(record.exploitFlags, 0),
      breachFlags: safePositiveInt(record.breachFlags, 0),
      highestRisk: safePositiveInt(record.highestRisk, 0, 100),
      lastRoute: safeString(record.lastRoute, 150),
      lastAction: safeString(record.lastAction, 30)
    }
  };
}

function analyzePayloadThreats({
  req,
  body,
  route,
  originAllowed
} = {}) {
  const method = normalizeMethod(req?.method || "");
  const contentType = normalizeContentType(getHeaderValue(req?.headers, "content-type"));
  const normalizedRoute = normalizeRoute(route);

  let threatScore = 0;
  const reasons = [];
  const events = {
    exploitSignals: 0,
    breachSignals: 0,
    malformedSignals: 0,
    methodSignals: 0
  };

  if (method === "INVALID") {
    threatScore += 30;
    reasons.push("invalid_method");
    events.methodSignals += 1;
    events.exploitSignals += 1;
  }

  const bodyIsObject = isPlainObject(body);
  const bodyKeys = bodyIsObject ? Object.keys(body).slice(0, 50) : [];
  const bodyString = safeString(
    bodyIsObject ? JSON.stringify(sanitizeMetadata(body, 0, 3, 20, 10)) : String(body ?? ""),
    3000
  ).toLowerCase();

  const suspiciousPatterns = [
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "union select",
    "drop table",
    " or 1=1",
    "../",
    "..\\",
    "/etc/passwd",
    "cmd.exe",
    "powershell",
    "wget ",
    "curl ",
    "${jndi:",
    "<iframe",
    "document.cookie"
  ];

  const matchedPatterns = suspiciousPatterns.filter((pattern) =>
    bodyString.includes(pattern)
  );

  if (matchedPatterns.length > 0) {
    threatScore += Math.min(50, matchedPatterns.length * 12);
    reasons.push("suspicious_payload_patterns");
    events.exploitSignals += matchedPatterns.length >= 2 ? 2 : 1;
  }

  if (
    ["post", "put", "patch"].includes((method || "").toLowerCase()) &&
    !contentType.includes("application/json") &&
    !contentType.includes("application/x-www-form-urlencoded") &&
    !contentType.includes("multipart/form-data") &&
    body &&
    Object.keys(body || {}).length > 0
  ) {
    threatScore += 15;
    reasons.push("unexpected_content_type");
    events.malformedSignals += 1;
  }

  if (!originAllowed && normalizedRoute !== "unknown-route") {
    threatScore += 10;
    reasons.push("untrusted_origin");
    events.malformedSignals += 1;
  }

  if (bodyKeys.length > 20) {
    threatScore += 10;
    reasons.push("oversized_body_key_count");
    events.malformedSignals += 1;
  }

  const sensitiveRoute =
    getRouteSensitivity(normalizedRoute) === "critical" ||
    getRouteSensitivity(normalizedRoute) === "high";

  if (
    sensitiveRoute &&
    (matchedPatterns.length > 0 || method === "INVALID")
  ) {
    threatScore += 20;
    reasons.push("sensitive_route_exploit_pressure");
    events.breachSignals += 1;
  }

  return {
    threatScore: Math.min(100, threatScore),
    reasons,
    matchedPatterns: matchedPatterns.slice(0, 10),
    events
  };
}

export function getCombinedRisk(
  botAnalysis,
  abuseAnalysis,
  payloadThreatAnalysis = null,
  extra = {}
) {
  let score = 0;

  score += safePositiveInt(botAnalysis?.riskScore, 0, 100);
  score += safePositiveInt(abuseAnalysis?.abuseScore, 0, 100);
  score += safePositiveInt(payloadThreatAnalysis?.threatScore, 0, 100);
  score += safePositiveInt(extra.modeRiskBonus, 0, 100);
  score += safePositiveInt(extra.actorRiskBonus, 0, 100);
  score += safePositiveInt(extra.routeRiskBonus, 0, 100);

  if (botAnalysis?.recommendedAction === "block") {
    score += 25;
  } else if (botAnalysis?.recommendedAction === "challenge") {
    score += 15;
  }

  if (abuseAnalysis?.recommendedAction === "block") {
    score += 25;
  } else if (abuseAnalysis?.recommendedAction === "challenge") {
    score += 15;
  }

  if (payloadThreatAnalysis?.events?.exploitSignals > 0) {
    score += 20;
  }

  if (payloadThreatAnalysis?.events?.breachSignals > 0) {
    score += 25;
  }

  if (safePositiveInt(abuseAnalysis?.snapshot?.suspiciousEvents, 0) >= 3) {
    score += 10;
  }

  return Math.min(100, score);
}

export function getFinalSecurityAction({
  rateLimitResult = null,
  botAnalysis = null,
  abuseAnalysis = null,
  payloadThreatAnalysis = null,
  combinedRisk = 0,
  securityMode = "normal",
  route = ""
} = {}) {
  const sensitivity = getRouteSensitivity(route);
  const exploitSignals = safePositiveInt(payloadThreatAnalysis?.events?.exploitSignals, 0);
  const breachSignals = safePositiveInt(payloadThreatAnalysis?.events?.breachSignals, 0);

  if (rateLimitResult && !rateLimitResult.allowed) {
    if (
      securityMode === "lockdown" ||
      sensitivity === "critical" ||
      rateLimitResult.recommendedAction === "block"
    ) {
      return "block";
    }

    if (rateLimitResult.recommendedAction === "challenge") {
      return "challenge";
    }

    return "throttle";
  }

  if (
    breachSignals > 0 ||
    exploitSignals >= 2 ||
    (securityMode === "lockdown" && sensitivity !== "normal")
  ) {
    return "block";
  }

  if (
    botAnalysis?.recommendedAction === "block" ||
    abuseAnalysis?.recommendedAction === "block" ||
    combinedRisk >= 90
  ) {
    return "block";
  }

  if (
    securityMode === "attack" &&
    sensitivity !== "normal" &&
    combinedRisk >= 50
  ) {
    return "challenge";
  }

  if (
    exploitSignals > 0 ||
    botAnalysis?.recommendedAction === "challenge" ||
    abuseAnalysis?.recommendedAction === "challenge" ||
    combinedRisk >= 60
  ) {
    return "challenge";
  }

  if (
    botAnalysis?.recommendedAction === "throttle" ||
    abuseAnalysis?.recommendedAction === "throttle" ||
    combinedRisk >= 40
  ) {
    return "throttle";
  }

  return "allow";
}

function getContainmentAction({
  finalAction = "allow",
  securityMode = "normal",
  route = "",
  payloadThreatAnalysis = null
} = {}) {
  const sensitivity = getRouteSensitivity(route);
  const breachSignals = safePositiveInt(payloadThreatAnalysis?.events?.breachSignals, 0);

  if (breachSignals > 0) {
    return "critical_containment";
  }

  if (securityMode === "lockdown" && sensitivity === "critical") {
    return "freeze_sensitive_route";
  }

  if (finalAction === "block") {
    return "temporary_containment";
  }

  if (finalAction === "challenge") {
    return "step_up_verification";
  }

  if (finalAction === "throttle") {
    return "slow_down_actor";
  }

  return "none";
}

export function buildRiskPayload({
  rateLimitResult = null,
  botAnalysis = null,
  abuseAnalysis = null,
  payloadThreatAnalysis = null,
  combinedRisk = 0,
  finalAction = "allow",
  securityMode = "normal",
  route = "",
  actorMemory = null,
  containmentAction = "none"
} = {}) {
  return {
    rateLimitAllowed: rateLimitResult ? Boolean(rateLimitResult.allowed) : true,
    rateLimitAction: rateLimitResult?.recommendedAction || "allow",
    botLevel: botAnalysis?.level || "low",
    botRecommendedAction: botAnalysis?.recommendedAction || "allow",
    abuseLevel: abuseAnalysis?.level || "low",
    abuseRecommendedAction: abuseAnalysis?.recommendedAction || "allow",
    payloadThreatScore: safePositiveInt(payloadThreatAnalysis?.threatScore, 0, 100),
    payloadThreatReasons: Array.isArray(payloadThreatAnalysis?.reasons)
      ? payloadThreatAnalysis.reasons.slice(0, 10).map((item) => safeString(item, 80))
      : [],
    combinedRisk: safePositiveInt(combinedRisk, 0, 100),
    finalAction: safeString(finalAction, 30),
    securityMode: safeString(securityMode, 30),
    routeSensitivity: getRouteSensitivity(route),
    containmentAction: safeString(containmentAction, 50),
    actorMemory: actorMemory
      ? {
          suspiciousCount: safePositiveInt(actorMemory.suspiciousCount, 0),
          blockedCount: safePositiveInt(actorMemory.blockedCount, 0),
          challengedCount: safePositiveInt(actorMemory.challengedCount, 0),
          exploitFlags: safePositiveInt(actorMemory.exploitFlags, 0),
          breachFlags: safePositiveInt(actorMemory.breachFlags, 0),
          highestRisk: safePositiveInt(actorMemory.highestRisk, 0, 100)
        }
      : null
  };
}

export function getSecurityModeSnapshot() {
  return {
    mode: safeString(securityStateStore.mode || "normal", 30),
    updatedAt: safePositiveInt(securityStateStore.updatedAt, Date.now()),
    lastEscalationReason: safeString(
      securityStateStore.lastEscalationReason || "",
      120
    ),
    recentSuspiciousEvents: safePositiveInt(
      securityStateStore.suspiciousEvents.length,
      0
    )
  };
}

export async function runRouteSecurity({
  req,
  route,
  rateLimit = null,
  allowedOrigins = [],
  body = {},
  behavior = {},
  sessionId = "",
  abuseSuccess = true,
  userId = ""
} = {}) {
  const normalizedRoute = normalizeRoute(route);
  const ip = getClientIp(req);
  const origin = normalizeOrigin(getHeaderValue(req?.headers, "origin"));
  const requestUserAgent = safeString(getHeaderValue(req?.headers, "user-agent"), 500);
  const method = normalizeMethod(req?.method || "");
  const contentType = normalizeContentType(getHeaderValue(req?.headers, "content-type"));

  const originAllowed = isAllowedOrigin(origin, allowedOrigins);
  const securityModeBefore = updateSecurityMode();

  const adaptiveMultiplier = getAdaptiveLimitMultiplier(
    securityModeBefore.mode,
    normalizedRoute
  );

  let rateLimitResult = null;
  if (rateLimit) {
    try {
      rateLimitResult = await checkApiRateLimit({
        key: safeString(rateLimit.key || `route:${normalizedRoute}:${ip}`, 200),
        limit: Math.max(
          1,
          Math.floor(safePositiveInt(rateLimit.limit, 60) * adaptiveMultiplier)
        ),
        windowMs: safePositiveInt(rateLimit.windowMs, 60 * 1000),
        route: normalizedRoute
      });
    } catch (error) {
      console.error("runRouteSecurity rate limit failed:", error);
      rateLimitResult = null;
    }
  }

  let abuseAnalysis = null;
  try {
    abuseAnalysis = await trackApiAbuse({
      ip,
      sessionId: safeString(sessionId || "", 120),
      userId: safeString(userId || "", 120),
      route: normalizedRoute,
      success: Boolean(abuseSuccess)
    });
  } catch (error) {
    console.error("runRouteSecurity abuse analysis failed:", error);
    abuseAnalysis = null;
  }

  let botAnalysis = null;
  try {
    botAnalysis = await trackBotBehavior(
      {
        ...(isPlainObject(behavior) ? behavior : {}),
        route: normalizedRoute,
        sessionId: safeString(sessionId || "", 120),
        body: sanitizeBody(body, 20)
      },
      req
    );
  } catch (error) {
    console.error("runRouteSecurity bot analysis failed:", error);
    botAnalysis = null;
  }

  const payloadThreatAnalysis = analyzePayloadThreats({
    req,
    body,
    route: normalizedRoute,
    originAllowed
  });

  const actorBaseline = getOrCreateActorMemory(ip, sessionId).record;
  const actorRiskBonus = getActorRiskBonus(actorBaseline);
  const modeRiskBonus = getSecurityModeRiskBonus(securityModeBefore.mode);
  const routeRiskBonus = getRouteRiskWeight(normalizedRoute) * 5;

  const combinedRisk = getCombinedRisk(
    botAnalysis,
    abuseAnalysis,
    payloadThreatAnalysis,
    {
      modeRiskBonus,
      actorRiskBonus,
      routeRiskBonus
    }
  );

  const finalAction = getFinalSecurityAction({
    rateLimitResult,
    botAnalysis,
    abuseAnalysis,
    payloadThreatAnalysis,
    combinedRisk,
    securityMode: securityModeBefore.mode,
    route: normalizedRoute
  });

  const actorUpdate = updateActorMemory({
    ip,
    sessionId,
    route: normalizedRoute,
    combinedRisk,
    finalAction,
    exploitSignals: payloadThreatAnalysis?.events?.exploitSignals || 0,
    breachSignals: payloadThreatAnalysis?.events?.breachSignals || 0
  });

  if (
    finalAction !== "allow" ||
    combinedRisk >= 60 ||
    safePositiveInt(payloadThreatAnalysis?.events?.exploitSignals, 0) > 0 ||
    safePositiveInt(payloadThreatAnalysis?.events?.breachSignals, 0) > 0
  ) {
    recordSuspiciousEvent({
      route: normalizedRoute,
      ip,
      finalAction,
      combinedRisk,
      reason: `${securityModeBefore.mode}:${finalAction}`,
      exploitSignals: payloadThreatAnalysis?.events?.exploitSignals || 0,
      breachSignals: payloadThreatAnalysis?.events?.breachSignals || 0
    });
  }

  const securityModeAfter = updateSecurityMode();
  const containmentAction = getContainmentAction({
    finalAction,
    securityMode: securityModeAfter.mode,
    route: normalizedRoute,
    payloadThreatAnalysis
  });

  return {
    ip,
    origin,
    originAllowed,
    requestUserAgent,
    method,
    contentType,
    rateLimitResult,
    abuseAnalysis,
    botAnalysis,
    payloadThreatAnalysis,
    combinedRisk,
    finalAction,
    containmentAction,
    routeSensitivity: getRouteSensitivity(normalizedRoute),
    actorKey: actorUpdate.actorKey,
    actorMemory: actorUpdate.actorMemory,
    securityMode: securityModeAfter.mode,
    securityModeSnapshot: getSecurityModeSnapshot(),
    riskPayload: buildRiskPayload({
      rateLimitResult,
      botAnalysis,
      abuseAnalysis,
      payloadThreatAnalysis,
      combinedRisk,
      finalAction,
      securityMode: securityModeAfter.mode,
      route: normalizedRoute,
      actorMemory: actorUpdate.actorMemory,
      containmentAction
    })
  };
}
