import { checkApiRateLimit } from "./_rate-limit.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";
import { analyzeBotBehavior } from "./_bot-detection.js";

export function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

export function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

export function safePositiveInt(value, fallback = 0) {
  const num = Math.floor(safeNumber(value, fallback));
  return num >= 0 ? num : fallback;
}

export function safeBoolean(value) {
  return Boolean(value);
}

export function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

export function getClientIp(req) {
  const forwarded = req?.headers?.["x-forwarded-for"];

  if (typeof forwarded === "string" && forwarded.length > 0) {
    const ip = forwarded.split(",")[0]?.trim();
    if (ip && ip.length < 100) {
      return ip;
    }
  }

  const realIp = req?.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp.length > 0 && realIp.length < 100) {
    return realIp.trim();
  }

  return safeString(req?.socket?.remoteAddress || "unknown", 100);
}

export function normalizeOrigin(origin = "") {
  return safeString(origin, 200).trim();
}

export function isAllowedOrigin(origin, allowedOrigins = []) {
  const normalizedOrigin = normalizeOrigin(origin);

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

export function sanitizeMetadata(value, depth = 0, maxDepth = 4, maxKeys = 20, maxArrayItems = 20) {
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

export function getCombinedRisk(botAnalysis, abuseAnalysis) {
  let score = 0;

  score += safePositiveInt(botAnalysis?.riskScore, 0);
  score += safePositiveInt(abuseAnalysis?.abuseScore, 0);

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
  combinedRisk = 0
} = {}) {
  if (rateLimitResult && !rateLimitResult.allowed) {
    if (rateLimitResult.recommendedAction === "block") {
      return "block";
    }

    if (rateLimitResult.recommendedAction === "challenge") {
      return "challenge";
    }

    return "throttle";
  }

  if (
    botAnalysis?.recommendedAction === "block" ||
    abuseAnalysis?.recommendedAction === "block" ||
    combinedRisk >= 90
  ) {
    return "block";
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

export function buildRiskPayload({
  rateLimitResult = null,
  botAnalysis = null,
  abuseAnalysis = null,
  combinedRisk = 0,
  finalAction = "allow"
} = {}) {
  return {
    rateLimitAllowed: rateLimitResult ? Boolean(rateLimitResult.allowed) : true,
    rateLimitAction: rateLimitResult?.recommendedAction || "allow",
    botLevel: botAnalysis?.level || "low",
    botRecommendedAction: botAnalysis?.recommendedAction || "allow",
    abuseLevel: abuseAnalysis?.level || "low",
    abuseRecommendedAction: abuseAnalysis?.recommendedAction || "allow",
    combinedRisk: safePositiveInt(combinedRisk, 0),
    finalAction: safeString(finalAction, 30)
  };
}

export function runRouteSecurity({
  req,
  route,
  rateLimit = null,
  allowedOrigins = [],
  body = {},
  behavior = {},
  sessionId = "",
  abuseSuccess = true
} = {}) {
  const ip = getClientIp(req);
  const origin = normalizeOrigin(req?.headers?.origin || "");
  const requestUserAgent = safeString(req?.headers?.["user-agent"] || "", 500);

  const originAllowed = isAllowedOrigin(origin, allowedOrigins);

  const rateLimitResult = rateLimit
    ? checkApiRateLimit({
        key: safeString(rateLimit.key || `route:${route}:${ip}`, 200),
        limit: safePositiveInt(rateLimit.limit, 60),
        windowMs: safePositiveInt(rateLimit.windowMs, 60 * 1000),
        route: safeString(route || "unknown-route", 150)
      })
    : null;

  const abuseAnalysis = trackApiAbuse({
    ip,
    sessionId: safeString(sessionId || "", 120),
    route: safeString(route || "unknown-route", 150),
    success: Boolean(abuseSuccess)
  });

  const botAnalysis = analyzeBotBehavior(
    {
      ...(isPlainObject(behavior) ? behavior : {}),
      route: safeString(route || "unknown-route", 150),
      sessionId: safeString(sessionId || "", 120)
    },
    req
  );

  const combinedRisk = getCombinedRisk(botAnalysis, abuseAnalysis);
  const finalAction = getFinalSecurityAction({
    rateLimitResult,
    botAnalysis,
    abuseAnalysis,
    combinedRisk
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
    riskPayload: buildRiskPayload({
      rateLimitResult,
      botAnalysis,
      abuseAnalysis,
      combinedRisk,
      finalAction
    })
  };
}
