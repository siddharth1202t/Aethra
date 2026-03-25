import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";

const MAX_HEADER_VALUE_LENGTH = 1000;
const MAX_KEY_LENGTH = 200;
const MAX_ROUTE_LENGTH = 180;
const MAX_ORIGIN_LENGTH = 200;
const MAX_HOST_LENGTH = 200;
const MAX_CONTENT_TYPE_LENGTH = 120;
const MAX_METHOD_LENGTH = 20;
const MAX_EMAIL_LENGTH = 200;

const ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "HEAD"
]);

/* -------------------- CORE SAFETY -------------------- */

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
  return value === true;
}

export function isPlainObject(value) {
  if (Object.prototype.toString.call(value) !== "[object Object]") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/* -------------------- HEADER / REQUEST HELPERS -------------------- */

export function getHeaderValue(headers, name) {
  if (!headers || !name) return "";

  const target = String(name).toLowerCase();

  if (typeof headers.get === "function") {
    return safeString(
      headers.get(name) || headers.get(target) || "",
      MAX_HEADER_VALUE_LENGTH
    );
  }

  if (isPlainObject(headers)) {
    for (const [key, value] of Object.entries(headers)) {
      if (String(key).toLowerCase() === target) {
        if (Array.isArray(value)) {
          return safeString(value[0] || "", MAX_HEADER_VALUE_LENGTH);
        }
        return safeString(value, MAX_HEADER_VALUE_LENGTH);
      }
    }
  }

  if (Array.isArray(headers)) {
    for (const entry of headers) {
      if (
        Array.isArray(entry) &&
        entry.length >= 2 &&
        String(entry[0]).toLowerCase() === target
      ) {
        return safeString(entry[1] || "", MAX_HEADER_VALUE_LENGTH);
      }
    }
  }

  return "";
}

export function normalizeIp(value = "") {
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
  if (cfIp) return normalizeIp(cfIp);

  const realIp = getHeaderValue(headers, "x-real-ip");
  if (realIp) return normalizeIp(realIp);

  const forwarded = getHeaderValue(headers, "x-forwarded-for");
  if (forwarded) return normalizeIp(forwarded.split(",")[0]?.trim());

  return normalizeIp(req?.ip || req?.socket?.remoteAddress || "unknown");
}

export function normalizeOrigin(origin = "") {
  const raw = safeString(origin, MAX_ORIGIN_LENGTH);

  if (!raw) return "";

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

export function normalizeHost(host = "") {
  return safeString(host || "", MAX_HOST_LENGTH).toLowerCase();
}

export function getRequestHost(req) {
  return normalizeHost(getHeaderValue(req?.headers, "host"));
}

export function normalizeMethod(method = "") {
  const normalized = safeString(method || "", MAX_METHOD_LENGTH).toUpperCase();
  if (!normalized) return "INVALID";
  return ALLOWED_METHODS.has(normalized) ? normalized : "INVALID";
}

export function normalizeContentType(value = "") {
  return safeString(value || "", MAX_CONTENT_TYPE_LENGTH).toLowerCase();
}

export function isJsonContentType(req) {
  return normalizeContentType(
    getHeaderValue(req?.headers, "content-type")
  ).includes("application/json");
}

export function normalizeRoute(route = "") {
  const raw = safeString(route || "unknown-route", MAX_ROUTE_LENGTH * 2);

  if (!raw) return "unknown-route";

  const cleaned = raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, MAX_ROUTE_LENGTH);

  return cleaned || "unknown-route";
}

export function normalizeKey(input = "") {
  const key = safeString(input || "", MAX_KEY_LENGTH).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  return key || "unknown";
}

export function normalizeEmail(value = "") {
  const email = safeString(value || "", MAX_EMAIL_LENGTH).toLowerCase();
  if (!email) return "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return "";
  return email;
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

/* -------------------- SANITIZATION -------------------- */

export function sanitizeBody(body, maxKeys = 20) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return {};
  }

  const entries = Object.entries(body).slice(0, maxKeys);
  const output = {};

  for (const [key, value] of entries) {
    const safeKey = safeString(key, 50);
    if (
      !safeKey ||
      safeKey === "__proto__" ||
      safeKey === "constructor" ||
      safeKey === "prototype"
    ) {
      continue;
    }
    output[safeKey] = value;
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
      const safeKey = safeString(key, 100);
      if (
        !safeKey ||
        safeKey === "__proto__" ||
        safeKey === "constructor" ||
        safeKey === "prototype"
      ) {
        continue;
      }

      output[safeKey] = sanitizeMetadata(
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

/* -------------------- RESPONSE BUILDERS -------------------- */

export function buildBlockedResponse(message, extra = {}) {
  return {
    success: false,
    ...extra,
    action: safeString(extra?.action || "block", 30).toLowerCase(),
    message: safeString(message || "Request blocked.", 300)
  };
}

export function buildSuccessResponse(extra = {}) {
  return {
    ...extra,
    success: true,
    action: "allow"
  };
}

export function buildDeniedResponse(message = "Request denied.", extra = {}) {
  return {
    success: false,
    ...extra,
    action: safeString(extra?.action || "deny", 30).toLowerCase(),
    message: safeString(message, 300)
  };
}

export function buildChallengeResponse(message = "Verification required.", extra = {}) {
  return {
    success: false,
    ...extra,
    action: "challenge",
    message: safeString(message, 300)
  };
}

export function buildMethodNotAllowedResponse(message = "Method not allowed.") {
  return {
    success: false,
    action: "deny",
    message: safeString(message, 300)
  };
}

/* -------------------- ROUTE SENSITIVITY -------------------- */

export function getRouteSensitivity(route = "") {
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

export function getRouteRiskWeight(route = "") {
  const sensitivity = getRouteSensitivity(route);

  if (sensitivity === "critical") return 3;
  if (sensitivity === "high") return 2;
  return 1;
}

/* -------------------- COMPATIBILITY SECURITY WRAPPER -------------------- */

export async function runRouteSecurity({
  env = {},
  req = null,
  route = "",
  body = {},
  behavior = {},
  context = {},
  allowedOrigins = null,
  sessionId = "",
  userId = "",
  abuseSuccess = true,
  rateLimitConfig = null,
  freshnessConfig = null,
  containmentConfig = {}
} = {}) {
  const normalizedRoute = normalizeRoute(route || req?.url || "unknown-route");
  const actor = createActorContext({
    req,
    body,
    behavior,
    context: {
      ...context,
      sessionId: context?.sessionId || sessionId,
      userId: context?.userId || userId
    },
    route: normalizedRoute
  });

  const origin = normalizeOrigin(getHeaderValue(req?.headers, "origin"));

  if (allowedOrigins && !isAllowedOrigin(origin, allowedOrigins)) {
    return {
      actor,
      ip: actor.ip,
      allowed: false,
      finalAction: "block",
      containmentAction: "temporary_containment",
      combinedRisk: 100,
      reason: "forbidden_origin",
      rateLimitResult: null,
      abuseResult: null,
      botResult: null,
      freshnessResult: null,
      threatResult: null,
      containmentResult: null,
      adaptiveModeResult: null,
      anomalyResult: null,
      alertsResult: null,
      risk: {
        riskScore: 100,
        finalAction: "block",
        finalContainmentAction: "temporary_containment",
        reasons: ["forbidden_origin"]
      },
      enforcement: {
        mustBlock: true,
        criticalAttack: false
      }
    };
  }

  const routeSensitivity = getRouteSensitivity(normalizedRoute);

  const orchestrated = await runSecurityOrchestrator({
    env,
    req,
    body,
    behavior,
    context: {
      ...context,
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId,
      email: actor.email || context?.email || body?.email || ""
    },
    route: normalizedRoute,
    rateLimitConfig:
      rateLimitConfig || {
        key: actor.routeKey || actor.actorKey,
        limit:
          routeSensitivity === "critical"
            ? 20
            : routeSensitivity === "high"
              ? 35
              : 60,
        windowMs: 60 * 1000
      },
    freshnessConfig,
    abuseSuccess,
    containmentConfig: {
      routeSensitivity,
      ...containmentConfig
    }
  });

  const finalAction = safeString(
    orchestrated?.risk?.finalAction || "allow",
    30
  ).toLowerCase();

  const finalContainmentAction = safeString(
    orchestrated?.risk?.finalContainmentAction || "none",
    50
  );

  return {
    actor,
    ip: actor.ip,
    allowed: finalAction === "allow",
    finalAction,
    containmentAction: finalContainmentAction,
    combinedRisk: safePositiveInt(orchestrated?.risk?.riskScore, 0, 100),
    reason: Array.isArray(orchestrated?.risk?.reasons)
      ? safeString(orchestrated.risk.reasons[0] || "", 120)
      : "",
    rateLimitResult: orchestrated?.signals?.rateLimitResult || null,
    abuseResult: orchestrated?.signals?.abuseResult || null,
    botResult: orchestrated?.signals?.botResult || null,
    freshnessResult: orchestrated?.signals?.freshnessResult || null,
    threatResult: orchestrated?.signals?.threatResult || null,
    containmentResult: orchestrated?.signals?.containmentResult || null,
    adaptiveModeResult: orchestrated?.signals?.adaptiveModeResult || null,
    anomalyResult: orchestrated?.signals?.anomalyResult || null,
    alertsResult: orchestrated?.signals?.alertsResult || null,
    risk: orchestrated?.risk || null,
    enforcement: orchestrated?.enforcement || null
  };
}
