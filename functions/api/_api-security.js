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

export function safeString(value, maxLength = 300) {
  return String(value || "")
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
  const forwarded = req?.headers?.["x-forwarded-for"];

  if (typeof forwarded === "string" && forwarded.length > 0) {
    return normalizeIp(forwarded.split(",")[0]?.trim());
  }

  if (Array.isArray(forwarded) && forwarded.length > 0) {
    return normalizeIp(String(forwarded[0]).split(",")[0]?.trim());
  }

  const realIp = req?.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp.length > 0) {
    return normalizeIp(realIp.trim());
  }

  return normalizeIp(req?.socket?.remoteAddress || "unknown");
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
      .map((item) => sanitizeMetadata(item, depth + 1, maxDepth, maxKeys, maxArrayItems));
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
  return `${normalizeIp(ip || "unknown")}::${safeString(sessionId || "no-session", 120).replace(/[^a-zA-Z0-9._:@/-]/g, "") || "no-session"}`;
}

function recordSuspiciousEvent({
  route = "unknown-route",
  ip = "unknown",
  finalAction = "allow",
  combinedRisk = 0,
  reason = ""
} = {}) {
  const now = Date.now();

  securityStateStore.suspiciousEvents.push({
    at: now,
    route: normalizeRoute(route),
    ip: normalizeIp(ip),
    finalAction: safeString(finalAction, 30).toLowerCase(),
    combinedRisk: safePositiveInt(combinedRisk, 0, 100),
    reason: safeString(reason, 120)
  });

  securityStateStore.suspiciousEvents = securityStateStore.suspiciousEvents
    .filter((item) => item && now - safeNumber(item.at, 0) <= SUSPICIOUS_EVENT_WINDOW_MS)
    .slice(-MAX_SUSPICIOUS_EVENTS);
}

function updateSecurityMode() {
  const now = Date.now();

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

  let mode = "normal";
  let reason = "stable_activity";

  if (recentBlocks >= 10 || recentHighRisk >= 20) {
    mode = "lockdown";
    reason = "high_block_or_high_risk_volume";
  } else if (recentBlocks >= 4 || recentChallenges >= 12 || recentHighRisk >= 10) {
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
  finalAction = "allow"
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
      highestRisk: safePositiveInt(record.highestRisk, 0, 100),
      lastRoute: safeString(record.lastRoute, 150),
      lastAction: safeString(record.lastAction, 30)
    }
  };
}

export function getCombinedRisk(botAnalysis, abuseAnalysis, extra = {}) {
  let score = 0;

  score += safePositiveInt(botAnalysis?.riskScore, 0, 100);
  score += safePositiveInt(abuseAnalysis?.abuseScore, 0, 100);
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

  if (safePositiveInt(abuseAnalysis?.snapshot?.suspiciousEvents, 0) >= 3) {
    score += 10;
  }

  return Math.min(100, score);
}

export function getFinalSecurityAction({
  rateLimitResult = null,
  botAnalysis = null,
  abuseAnalysis = null,
  combinedRisk = 0,
  securityMode = "normal",
  route = ""
} = {}) {
  const sensitivity = getRouteSensitivity(route);

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
    securityMode === "lockdown" &&
    (sensitivity === "critical" || combinedRisk >= 50)
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
  route = ""
} = {}) {
  const sensitivity = getRouteSensitivity(route);

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
          highestRisk: safePositiveInt(actorMemory.highestRisk, 0, 100)
        }
      : null
  };
}

export function getSecurityModeSnapshot() {
  return {
    mode: safeString(securityStateStore.mode || "normal", 30),
    updatedAt: safePositiveInt(securityStateStore.updatedAt, Date.now()),
    lastEscalationReason: safeString(securityStateStore.lastEscalationReason || "", 120),
    recentSuspiciousEvents: safePositiveInt(securityStateStore.suspiciousEvents.length, 0)
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
  const origin = normalizeOrigin(req?.headers?.origin || "");
  const requestUserAgent = safeString(req?.headers?.["user-agent"] || "", 500);

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
    botAnalysis = await analyzeBotBehavior(
      {
        ...(isPlainObject(behavior) ? behavior : {}),
        route: normalizedRoute,
        sessionId: safeString(sessionId || "", 120)
      },
      req
    );
  } catch (error) {
    console.error("runRouteSecurity bot analysis failed:", error);
    botAnalysis = null;
  }

  const actorBaseline = getOrCreateActorMemory(ip, sessionId).record;
  const actorRiskBonus = getActorRiskBonus(actorBaseline);
  const modeRiskBonus = getSecurityModeRiskBonus(securityModeBefore.mode);
  const routeRiskBonus = getRouteRiskWeight(normalizedRoute) * 5;

  const combinedRisk = getCombinedRisk(botAnalysis, abuseAnalysis, {
    modeRiskBonus,
    actorRiskBonus,
    routeRiskBonus
  });

  const finalAction = getFinalSecurityAction({
    rateLimitResult,
    botAnalysis,
    abuseAnalysis,
    combinedRisk,
    securityMode: securityModeBefore.mode,
    route: normalizedRoute
  });

  const actorUpdate = updateActorMemory({
    ip,
    sessionId,
    route: normalizedRoute,
    combinedRisk,
    finalAction
  });

  if (finalAction !== "allow" || combinedRisk >= 60) {
    recordSuspiciousEvent({
      route: normalizedRoute,
      ip,
      finalAction,
      combinedRisk,
      reason: `${securityModeBefore.mode}:${finalAction}`
    });
  }

  const securityModeAfter = updateSecurityMode();
  const containmentAction = getContainmentAction({
    finalAction,
    securityMode: securityModeAfter.mode,
    route: normalizedRoute
  });

  return {
    ip,
    origin,
    originAllowed,
    requestUserAgent,
    rateLimitResult,
    abuseAnalysis,
    botAnalysis,
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
      combinedRisk,
      finalAction,
      securityMode: securityModeAfter.mode,
      route: normalizedRoute,
      actorMemory: actorUpdate.actorMemory,
      containmentAction
    })
  };
}
