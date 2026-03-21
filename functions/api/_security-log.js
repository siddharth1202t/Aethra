import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  safeNumber,
  isPlainObject,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse,
  runRouteSecurity
} from "./_api-security.js";
import { validateFreshRequest } from "./_request-freshness.js";

const ROUTE = "/api/security-log";

const ALLOWED_ORIGINS = new Set([
  "127.0.0.1",
  "https://aethra-hb2h.vercel.app",
  "localhost"
]);

const ALLOWED_HOSTNAMES = new Set([
  "127.0.0.1",
  "aethra-hb2h.vercel.app",
  "localhost"
]);

const ALLOWED_CLIENT_TYPES = new Set([
  "captcha_missing",
  "client_security_event",
  "page_error",
  "suspicious_client_behavior"
]);

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error"
]);

const MAX_BODY_KEYS = 14;
const MAX_EVENT_AGE_MS = 2 * 60 * 1000;
const EVENT_FUTURE_TOLERANCE_MS = 15 * 1000;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

function setNoStore(res) {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

function normalizeEmail(value = "") {
  const email = safeString(value || "", 200).toLowerCase();
  if (!email) return "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return "";
  }
  return email;
}

function normalizeEmailHash(value = "") {
  return safeString(value || "", 128)
    .toLowerCase()
    .replace(/[^a-f0-9]/g, "")
    .slice(0, 64);
}

function normalizeUserId(value = "") {
  return safeString(value || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function normalizeHostname(hostname = "") {
  return safeString(hostname || "", 200).trim().toLowerCase();
}

function normalizeOrigin(origin = "") {
  const raw = safeString(origin || "", 200).trim();
  if (!raw) return "";

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

function getRequestHost(req) {
  const hostHeader = safeString(req?.headers?.host || "", 200).toLowerCase();
  return normalizeHostname(hostHeader.split(":")[0] || "");
}

function getRefererOrigin(req) {
  const referer = safeString(req?.headers?.referer || "", 500).trim();

  if (!referer) {
    return "";
  }

  try {
    return new URL(referer).origin.toLowerCase();
  } catch {
    return "";
  }
}

function isHostAllowed(req) {
  return ALLOWED_HOSTNAMES.has(getRequestHost(req));
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(normalizeOrigin(origin));
}

function isJsonContentType(req) {
  const contentType = safeString(req?.headers?.["content-type"] || "", 200)
    .toLowerCase();
  return contentType.startsWith("application/json");
}

function getRequestContentLength(req) {
  const raw = req?.headers?.["content-length"];
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function safeClientType(type) {
  const normalized = safeString(type || "client_security_event", 50).toLowerCase();
  return ALLOWED_CLIENT_TYPES.has(normalized)
    ? normalized
    : "client_security_event";
}

function safeLevel(level) {
  const normalized = safeString(level || "warning", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "warning";
}

function sanitizeClient(client = {}) {
  return {
    userAgent: safeString(client.userAgent || "", 300),
    language: safeString(client.language || "", 50),
    platform: safeString(client.platform || "", 100),
    screenWidth: Math.max(0, safeNumber(client.screenWidth, 0)),
    screenHeight: Math.max(0, safeNumber(client.screenHeight, 0)),
    viewportWidth: Math.max(0, safeNumber(client.viewportWidth, 0)),
    viewportHeight: Math.max(0, safeNumber(client.viewportHeight, 0)),
    pixelRatio: Math.max(0, safeNumber(client.pixelRatio, 1)),
    hardwareConcurrency: Math.max(0, safeNumber(client.hardwareConcurrency, 0)),
    deviceMemory: Math.max(0, safeNumber(client.deviceMemory, 0)),
    url: safeString(client.url || "", 300),
    referrer: safeString(client.referrer || "", 300),
    timezone: safeString(client.timezone || "", 100),
    visibilityState: safeString(client.visibilityState || "", 30),
    telemetryVersion: Math.max(0, safeNumber(client.telemetryVersion, 0)),
    online: client.online === true,
    webdriver: client.webdriver === true
  };
}

function buildTelemetryNonceScope(type = "") {
  return `security-log:${safeClientType(type)}`;
}

export default async function handler(req, res) {
  setNoStore(res);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json(buildMethodNotAllowedResponse());
  }

  if (!isJsonContentType(req)) {
    return res.status(415).json({
      success: false,
      message: "Unsupported content type."
    });
  }

  if (getRequestContentLength(req) > MAX_CONTENT_LENGTH_BYTES) {
    return res.status(413).json({
      success: false,
      message: "Request body too large."
    });
  }

  let ip = "unknown";

  try {
    const body = sanitizeBody(req.body, MAX_BODY_KEYS);
    const behavior =
      body.behavior && isPlainObject(body.behavior)
        ? body.behavior
        : {};
    const sessionId = safeString(body.sessionId || "", 120);
    const requestHost = getRequestHost(req);
    const refererOrigin = getRefererOrigin(req);

    if (!isHostAllowed(req)) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Blocked client security log request on forbidden host",
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          blockedReason: "forbidden_host",
          host: requestHost,
          refererOrigin
        }
      });

      return res.status(403).json(
        buildBlockedResponse("Forbidden host.", { action: "block" })
      );
    }

    const security = await runRouteSecurity({
      req,
      route: ROUTE,
      allowedOrigins: ALLOWED_ORIGINS,
      rateLimit: {
        key: `security-log:${safeString(
          req?.headers?.["x-forwarded-for"] ||
            req?.headers?.["x-real-ip"] ||
            req?.socket?.remoteAddress ||
            "unknown",
          100
        )}`,
        limit: 20,
        windowMs: 5 * 60 * 1000
      },
      body,
      behavior,
      sessionId,
      abuseSuccess: true,
      userId: normalizeUserId(body.userId || "")
    });

    ip = security.ip;
    const origin = security.origin;

    if (!security.originAllowed || !isOriginAllowed(origin)) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Blocked client security log request from forbidden origin",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          blockedReason: "forbidden_origin",
          requestOrigin: origin,
          refererOrigin,
          requestUserAgent: security.requestUserAgent,
          host: requestHost,
          sessionId
        }
      });

      return res.status(403).json(
        buildBlockedResponse("Forbidden origin.", { action: "block" })
      );
    }

    if (security.rateLimitResult && !security.rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Security log endpoint rate limited",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action: security.rateLimitResult.recommendedAction,
          remainingMs: security.rateLimitResult.remainingMs || 0,
          violations: security.rateLimitResult.violations || 0,
          sessionId
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests.",
        action: security.rateLimitResult.recommendedAction,
        remainingMs: security.rateLimitResult.remainingMs || 0
      });
    }

    if (security.finalAction === "block") {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Blocked suspicious client telemetry request",
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          abuseAnalysis: security.abuseAnalysis,
          botAnalysis: security.botAnalysis,
          combinedRisk: security.combinedRisk,
          finalAction: security.finalAction,
          sessionId
        })
      });

      return res.status(403).json(
        buildBlockedResponse("Suspicious request blocked.", {
          action: "block"
        })
      );
    }

    if (security.finalAction === "challenge") {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Challenge required for suspicious client telemetry request",
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          abuseAnalysis: security.abuseAnalysis,
          botAnalysis: security.botAnalysis,
          combinedRisk: security.combinedRisk,
          finalAction: security.finalAction,
          sessionId
        })
      });

      return res.status(403).json(
        buildBlockedResponse("Verification required.", {
          action: "challenge"
        })
      );
    }

    if (security.finalAction === "throttle") {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Throttled suspicious client telemetry request",
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          abuseAnalysis: security.abuseAnalysis,
          botAnalysis: security.botAnalysis,
          combinedRisk: security.combinedRisk,
          finalAction: security.finalAction,
          sessionId
        })
      });
    }

    const type = safeClientType(body.type);
    const level = safeLevel(body.level);
    const message = safeString(body.message || "", 500);
    const email = normalizeEmail(body.email || "");
    const emailHash = normalizeEmailHash(body.emailHash || "");
    const userId = normalizeUserId(body.userId || "");
    const metadata = sanitizeMetadata(
      isPlainObject(body.metadata) ? body.metadata : {}
    );
    const client = sanitizeClient(
      isPlainObject(body.client) ? body.client : {}
    );

    const freshRequestResult = await validateFreshRequest({
      requestAt: body.eventAt,
      nonce: safeString(body.nonce || "", 200),
      scope: buildTelemetryNonceScope(type),
      requireNonce: Boolean(safeString(body.nonce || "", 200)),
      maxAgeMs: MAX_EVENT_AGE_MS,
      futureToleranceMs: EVENT_FUTURE_TOLERANCE_MS,
      nonceTtlMs: 10 * 60 * 1000
    });

    if (!freshRequestResult.ok) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Rejected replayed or invalid client telemetry request",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          freshnessCode: safeString(freshRequestResult.code || "", 100),
          ageMs: safeNumber(freshRequestResult.ageMs, 0),
          requestUserAgent: security.requestUserAgent,
          sessionId
        }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid telemetry request."
      });
    }

    await writeSecurityLog({
      type,
      level,
      message: message || "Client security telemetry received",
      email,
      emailHash,
      userId,
      ip,
      route: ROUTE,
      metadata: {
        source: "client_untrusted",
        eventAt: safeNumber(body.eventAt, 0),
        receivedAt: Date.now(),
        ageMs: safeNumber(freshRequestResult.ageMs, 0),
        requestOrigin: origin,
        requestUserAgent: security.requestUserAgent,
        requestHost,
        refererOrigin,
        sessionId,
        sessionIdPresent: Boolean(sessionId),
        noncePresent: Boolean(safeString(body.nonce || "", 200)),
        metadata,
        client
      }
    });

    return res.status(200).json({
      success: true,
      action: security.finalAction === "allow" ? "allow" : security.finalAction
    });
  } catch (error) {
    console.error("Security log API error:", error);

    try {
      await writeSecurityLog({
        type: "client_security_event",
        level: "error",
        message: "Unhandled server error in security-log API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          error: safeString(error?.message || "Unknown error", 500)
        }
      });
    } catch (logError) {
      console.error("Nested security log write failed:", logError);
    }

    return res.status(500).json({
      success: false,
      message: "Internal server error."
    });
  }
}
