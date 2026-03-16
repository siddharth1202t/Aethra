const MAX_IP_LENGTH = 100;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_USER_ID_LENGTH = 128;
const MAX_ROUTE_LENGTH = 150;
const MAX_USER_AGENT_LENGTH = 500;
const MAX_ORIGIN_LENGTH = 200;
const MAX_METHOD_LENGTH = 20;
const MAX_EMAIL_LENGTH = 200;

function safeString(value, maxLength = 300) {
  return String(value || "").trim().slice(0, maxLength);
}

function normalizeIp(value = "") {
  return safeString(value || "unknown", MAX_IP_LENGTH);
}

function normalizeSessionId(value = "") {
  return safeString(value || "", MAX_SESSION_ID_LENGTH);
}

function normalizeUserId(value = "") {
  return safeString(value || "", MAX_USER_ID_LENGTH);
}

function normalizeRoute(value = "") {
  return safeString(value || "unknown-route", MAX_ROUTE_LENGTH).toLowerCase();
}

function normalizeUserAgent(value = "") {
  return safeString(value || "", MAX_USER_AGENT_LENGTH);
}

function normalizeOrigin(value = "") {
  return safeString(value || "", MAX_ORIGIN_LENGTH).toLowerCase();
}

function normalizeMethod(value = "") {
  return safeString(value || "GET", MAX_METHOD_LENGTH).toUpperCase();
}

function normalizeEmail(value = "") {
  return safeString(value || "", MAX_EMAIL_LENGTH).toLowerCase();
}

function getHeaderValue(req, name) {
  const value = req?.headers?.[name];

  if (Array.isArray(value)) {
    return safeString(value[0] || "", 500);
  }

  return safeString(value || "", 500);
}

function extractClientIp(req = null, fallback = "") {
  const forwarded = req?.headers?.["x-forwarded-for"];

  if (typeof forwarded === "string" && forwarded.trim()) {
    return normalizeIp(forwarded.split(",")[0].trim());
  }

  if (Array.isArray(forwarded) && forwarded.length > 0) {
    return normalizeIp(String(forwarded[0]).split(",")[0].trim());
  }

  const realIp = getHeaderValue(req, "x-real-ip");
  if (realIp) {
    return normalizeIp(realIp);
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

function extractUserAgent(req = null, fallback = "") {
  return normalizeUserAgent(getHeaderValue(req, "user-agent") || fallback);
}

function extractRoute(req = null, fallback = "") {
  return normalizeRoute(req?.url || fallback);
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
    context.sessionId ||
    body.sessionId ||
    behavior.sessionId ||
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
    context.userId ||
    body.userId ||
    req?.user?.uid ||
    req?.auth?.uid ||
    fallback
  );
}

function buildActorKey({
  ip = "",
  sessionId = "",
  userId = ""
} = {}) {
  return [
    normalizeIp(ip || "unknown"),
    normalizeSessionId(sessionId || "no-session"),
    normalizeUserId(userId || "anon-user")
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

export function createActorContext({
  req = null,
  body = {},
  behavior = {},
  context = {},
  route = "",
  fallbackIp = "",
  fallbackSessionId = "",
  fallbackUserId = ""
} = {}) {
  const ip = extractClientIp(req, context.ip || fallbackIp);
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
  const userAgent = extractUserAgent(req, safeString(behavior.userAgent || "", MAX_USER_AGENT_LENGTH));
  const email = normalizeEmail(body.email || context.email || "");

  return {
    ip,
    sessionId,
    userId,
    route: resolvedRoute,
    method,
    origin,
    userAgent,
    email,
    actorKey: buildActorKey({ ip, sessionId, userId }),
    routeActorKey: buildRouteScopedKey({
      ip,
      sessionId,
      userId,
      route: resolvedRoute
    })
  };
}

export {
  safeString,
  normalizeIp,
  normalizeSessionId,
  normalizeUserId,
  normalizeRoute,
  normalizeUserAgent,
  normalizeOrigin,
  normalizeMethod,
  normalizeEmail,
  extractClientIp,
  extractOrigin,
  extractUserAgent,
  extractRoute,
  extractMethod,
  extractSessionId,
  extractUserId,
  buildActorKey,
  buildRouteScopedKey
};
