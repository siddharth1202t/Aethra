const MAX_IP_LENGTH = 100;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_USER_ID_LENGTH = 128;
const MAX_ROUTE_LENGTH = 180;
const MAX_USER_AGENT_LENGTH = 500;
const MAX_ORIGIN_LENGTH = 200;
const MAX_METHOD_LENGTH = 20;
const MAX_EMAIL_LENGTH = 200;
const MAX_HEADER_VALUE_LENGTH = 500;
const MAX_REQUEST_ID_LENGTH = 120;
const MAX_HOST_LENGTH = 200;
const MAX_REFERER_LENGTH = 300;

const ALLOWED_METHODS = new Set([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "HEAD"
]);

function stripControlChars(value = "") {
  return String(value ?? "").replace(/[\u0000-\u001F\u007F]/g, "");
}

function safeString(value, maxLength = 300) {
  return stripControlChars(value).trim().slice(0, maxLength);
}

function sanitizeKeyPart(value = "", maxLength = 120) {
  return safeString(value, maxLength).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function getHeaderValue(req, name) {
  const headers = req?.headers;
  if (!headers || !name) return "";

  const target = String(name).toLowerCase();

  if (typeof headers.get === "function") {
    return safeString(headers.get(name) || headers.get(target) || "", MAX_HEADER_VALUE_LENGTH);
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
    return "";
  }

  if (isPlainObject(headers)) {
    for (const [key, value] of Object.entries(headers)) {
      if (String(key).toLowerCase() === target) {
        if (Array.isArray(value)) {
          return safeString(value[0] || "", MAX_HEADER_VALUE_LENGTH);
        }
        return safeString(value || "", MAX_HEADER_VALUE_LENGTH);
      }
    }
  }

  return "";
}

function normalizeIp(value = "") {
  let ip = safeString(value || "unknown", MAX_IP_LENGTH);
  if (!ip) return "unknown";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, MAX_IP_LENGTH);
  return ip || "unknown";
}

function normalizeSessionId(value = "") {
  return sanitizeKeyPart(value || "", MAX_SESSION_ID_LENGTH);
}

function normalizeUserId(value = "") {
  return sanitizeKeyPart(value || "", MAX_USER_ID_LENGTH);
}

function normalizeRequestId(value = "") {
  return sanitizeKeyPart(value || "", MAX_REQUEST_ID_LENGTH);
}

function normalizeRoute(value = "") {
  const raw = safeString(value || "unknown-route", MAX_ROUTE_LENGTH * 2);
  if (!raw) return "unknown-route";

  const withoutQuery = raw.split("?")[0].split("#")[0];

  const cleaned = withoutQuery
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, MAX_ROUTE_LENGTH);

  return cleaned || "unknown-route";
}

function normalizeUserAgent(value = "") {
  return safeString(value || "", MAX_USER_AGENT_LENGTH);
}

function normalizeOrigin(value = "") {
  const raw = safeString(value || "", MAX_ORIGIN_LENGTH);
  if (!raw) return "";

  try {
    const parsed = new URL(raw);
    return safeString(parsed.origin.toLowerCase(), MAX_ORIGIN_LENGTH);
  } catch {
    return "";
  }
}

function normalizeHost(value = "") {
  return safeString(value || "", MAX_HOST_LENGTH).toLowerCase();
}

function normalizeReferer(value = "") {
  const raw = safeString(value || "", MAX_REFERER_LENGTH);
  if (!raw) return "";

  try {
    const parsed = new URL(raw);
    return safeString(parsed.toString(), MAX_REFERER_LENGTH);
  } catch {
    return "";
  }
}

function normalizeMethod(value = "") {
  const method = safeString(value || "", MAX_METHOD_LENGTH).toUpperCase();
  if (!method) return "INVALID";
  return ALLOWED_METHODS.has(method) ? method : "INVALID";
}

function normalizeEmail(value = "") {
  const email = safeString(value || "", MAX_EMAIL_LENGTH).toLowerCase();
  if (!email) return "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return "";
  return email;
}

function extractClientIp(req = null, fallback = "", options = {}) {
  const { trustForwardedFor = false } = options;

  // Prefer Cloudflare-provided client IP first
  const cfIp = getHeaderValue(req, "cf-connecting-ip");
  if (cfIp) {
    return normalizeIp(cfIp);
  }

  const realIp = getHeaderValue(req, "x-real-ip");
  if (realIp) {
    return normalizeIp(realIp);
  }

  if (trustForwardedFor) {
    const forwarded = getHeaderValue(req, "x-forwarded-for");
    if (forwarded) {
      return normalizeIp(forwarded.split(",")[0]?.trim());
    }
  }

  const socketIp = safeString(req?.socket?.remoteAddress || "", MAX_IP_LENGTH);
  if (socketIp) {
    return normalizeIp(socketIp);
  }

  return normalizeIp(fallback);
}

function extractOrigin(req = null) {
  return normalizeOrigin(getHeaderValue(req, "origin"));
}

function extractReferer(req = null) {
  return normalizeReferer(getHeaderValue(req, "referer"));
}

function extractHost(req = null) {
  return normalizeHost(getHeaderValue(req, "host"));
}

function extractUserAgent(req = null, fallback = "") {
  return normalizeUserAgent(getHeaderValue(req, "user-agent") || fallback);
}

function extractRoute(req = null, fallback = "") {
  const rawUrl = safeString(req?.url || "", MAX_ROUTE_LENGTH * 3);

  if (!rawUrl && fallback) {
    return normalizeRoute(fallback);
  }

  try {
    // supports relative URLs too
    const parsed = new URL(rawUrl, "https://local.aethra.internal");
    return normalizeRoute(parsed.pathname || fallback);
  } catch {
    return normalizeRoute(rawUrl || fallback);
  }
}

function extractMethod(req = null, fallback = "GET") {
  return normalizeMethod(req?.method || fallback);
}

function extractSessionId({
  body = {},
  behavior = {},
  context = {},
  fallback = ""
} = {}) {
  return normalizeSessionId(
    context?.sessionId ||
      body?.sessionId ||
      behavior?.sessionId ||
      fallback
  );
}

function extractUserId({
  body = {},
  context = {},
  req = null,
  fallback = ""
} = {}) {
  return normalizeUserId(
    context?.userId ||
      body?.userId ||
      req?.user?.uid ||
      req?.auth?.uid ||
      fallback
  );
}

function extractRequestId(req = null, context = {}) {
  return normalizeRequestId(
    context?.requestId ||
      getHeaderValue(req, "cf-ray") ||
      getHeaderValue(req, "x-request-id") ||
      getHeaderValue(req, "x-correlation-id")
  );
}

function buildActorKey({
  ip = "",
  sessionId = "",
  userId = ""
} = {}) {
  return [
    normalizeIp(ip || "unknown"),
    normalizeSessionId(sessionId || "no-session") || "no-session",
    normalizeUserId(userId || "anon-user") || "anon-user"
  ].join("::");
}

function buildRouteScopedKey({
  ip = "",
  sessionId = "",
  userId = "",
  route = ""
} = {}) {
  return `${buildActorKey({ ip, sessionId, userId })}::${normalizeRoute(route)}`;
}

function buildDeviceKey({
  userAgent = "",
  origin = "",
  host = ""
} = {}) {
  const ua = normalizeUserAgent(userAgent || "") || "no-ua";
  const normalizedOrigin = normalizeOrigin(origin || "") || "no-origin";
  const normalizedHost = normalizeHost(host || "") || "no-host";
  return `${ua}::${normalizedOrigin}::${normalizedHost}`;
}

export function createActorContext({
  req = null,
  body = {},
  behavior = {},
  context = {},
  route = "",
  fallbackIp = "",
  fallbackSessionId = "",
  fallbackUserId = "",
  trustForwardedFor = false
} = {}) {
  const ip = extractClientIp(req, context?.ip || fallbackIp, { trustForwardedFor });
  const sessionId = extractSessionId({
    body,
    behavior,
    context,
    fallback: fallbackSessionId
  });
  const userId = extractUserId({
    body,
    context,
    req,
    fallback: fallbackUserId
  });
  const resolvedRoute = extractRoute(req, route);
  const method = extractMethod(req, "GET");
  const origin = extractOrigin(req);
  const referer = extractReferer(req);
  const host = extractHost(req);
  const userAgent = extractUserAgent(
    req,
    safeString(behavior?.userAgent || "", MAX_USER_AGENT_LENGTH)
  );
  const email = normalizeEmail(body?.email || context?.email || "");
  const requestId = extractRequestId(req, context);
  const actorKey = buildActorKey({ ip, sessionId, userId });
  const routeActorKey = buildRouteScopedKey({
    ip,
    sessionId,
    userId,
    route: resolvedRoute
  });
  const deviceKey = buildDeviceKey({ userAgent, origin, host });

  return Object.freeze({
    ip,
    sessionId,
    userId,
    route: resolvedRoute,
    method,
    origin,
    referer,
    host,
    userAgent,
    email,
    requestId,
    actorKey,
    routeActorKey,
    deviceKey
  });
}

export {
  safeString,
  normalizeIp,
  normalizeSessionId,
  normalizeUserId,
  normalizeRequestId,
  normalizeRoute,
  normalizeUserAgent,
  normalizeOrigin,
  normalizeHost,
  normalizeReferer,
  normalizeMethod,
  normalizeEmail,
  extractClientIp,
  extractOrigin,
  extractReferer,
  extractHost,
  extractUserAgent,
  extractRoute,
  extractMethod,
  extractSessionId,
  extractUserId,
  extractRequestId,
  buildActorKey,
  buildRouteScopedKey,
  buildDeviceKey
};
