import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  safeNumber,
  safeBoolean,
  isPlainObject,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse,
  runRouteSecurity
} from "./_api-security.js";

const ROUTE = "/api/security-log";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
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

const MAX_BODY_KEYS = 12;
const MAX_EVENT_AGE_MS = 2 * 60 * 1000;

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
    screenWidth: safeNumber(client.screenWidth, 0),
    screenHeight: safeNumber(client.screenHeight, 0),
    url: safeString(client.url || "", 500),
    referrer: safeString(client.referrer || "", 500)
  };
}

function getEventFreshness(eventAt) {
  const now = Date.now();
  const safeEventAt = safeNumber(eventAt, 0);

  if (!safeEventAt) {
    return {
      valid: false,
      ageMs: null,
      reason: "missing_event_timestamp"
    };
  }

  const ageMs = now - safeEventAt;

  if (ageMs < -15_000) {
    return {
      valid: false,
      ageMs,
      reason: "future_event_timestamp"
    };
  }

  if (ageMs > MAX_EVENT_AGE_MS) {
    return {
      valid: false,
      ageMs,
      reason: "stale_event_timestamp"
    };
  }

  return {
    valid: true,
    ageMs,
    reason: null
  };
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json(buildMethodNotAllowedResponse());
  }

  let ip = "unknown";

  try {
    const body = sanitizeBody(req.body, MAX_BODY_KEYS);
    const behavior =
      body.behavior && isPlainObject(body.behavior)
        ? body.behavior
        : {};
    const sessionId = safeString(body.sessionId || "", 120);

    const security = runRouteSecurity({
      req,
      route: ROUTE,
      allowedOrigins: ALLOWED_ORIGINS,
      rateLimit: {
        key: `security-log:${safeString(req?.headers?.["x-forwarded-for"] || req?.headers?.["x-real-ip"] || req?.socket?.remoteAddress || "unknown", 100)}`,
        limit: 20,
        windowMs: 5 * 60 * 1000
      },
      body,
      behavior,
      sessionId,
      abuseSuccess: true
    });

    ip = security.ip;
    const origin = security.origin;

    if (!security.originAllowed) {
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
          requestUserAgent: security.requestUserAgent
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
          violations: security.rateLimitResult.violations || 0
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests.",
        action: security.rateLimitResult.recommendedAction,
        remainingMs: security.rateLimitResult.remainingMs || 0
      });
    }

    if (
      security.finalAction === "block" ||
      security.finalAction === "challenge"
    ) {
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
          finalAction: security.finalAction
        })
      });

      return res.status(403).json(
        buildBlockedResponse("Suspicious request blocked.", {
          action: security.finalAction
        })
      );
    }

    const type = safeClientType(body.type);
    const level = safeLevel(body.level);
    const message = safeString(body.message || "", 500);
    const email = safeString(body.email || "", 200);
    const userId = safeString(body.userId || "", 128);
    const metadata = sanitizeMetadata(body.metadata || {});
    const client = sanitizeClient(body.client || {});
    const eventFreshness = getEventFreshness(body.eventAt);

    if (!eventFreshness.valid) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Rejected stale or invalid client telemetry timestamp",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          freshnessReason: eventFreshness.reason,
          ageMs: eventFreshness.ageMs,
          requestUserAgent: security.requestUserAgent
        }
      });

      return res.status(400).json({
        success: false,
        message: "Invalid event timestamp."
      });
    }

    await writeSecurityLog({
      type,
      level,
      message: message || "Client security telemetry received",
      email,
      userId,
      ip,
      route: ROUTE,
      metadata: {
        source: "client_untrusted",
        eventAt: safeNumber(body.eventAt, 0),
        receivedAt: Date.now(),
        ageMs: eventFreshness.ageMs,
        requestOrigin: origin,
        requestUserAgent: security.requestUserAgent,
        sessionIdPresent: safeBoolean(body.sessionId),
        metadata,
        client
      }
    });

    return res.status(200).json({
      success: true
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
