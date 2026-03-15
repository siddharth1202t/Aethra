import { writeSecurityLog } from "./_security-log.js";
import { checkApiRateLimit } from "./_rate-limit.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";

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

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeBoolean(value) {
  return Boolean(value);
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (typeof forwarded === "string" && forwarded.length > 0) {
    const ip = forwarded.split(",")[0]?.trim();
    if (ip && ip.length < 100) {
      return ip;
    }
  }

  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.length > 0 && realIp.length < 100) {
    return realIp.trim();
  }

  return safeString(req.socket?.remoteAddress || "unknown", 100);
}

function isAllowedOrigin(origin) {
  return ALLOWED_ORIGINS.has(origin);
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
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

function sanitizeMetadata(value, depth = 0) {
  if (depth > 4) {
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
    return value.slice(0, 20).map((item) => sanitizeMetadata(item, depth + 1));
  }

  if (isPlainObject(value)) {
    const output = {};
    const entries = Object.entries(value).slice(0, 20);

    for (const [key, val] of entries) {
      output[safeString(key, 100)] = sanitizeMetadata(val, depth + 1);
    }

    return output;
  }

  return safeString(value, 500);
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

function sanitizeBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return {};
  }

  const entries = Object.entries(body).slice(0, MAX_BODY_KEYS);
  const output = {};

  for (const [key, value] of entries) {
    output[safeString(key, 50)] = value;
  }

  return output;
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
  const ip = getClientIp(req);

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed."
    });
  }

  try {
    const origin = safeString(req.headers.origin || "", 200);
    const requestUserAgent = safeString(req.headers["user-agent"] || "", 500);
    const body = sanitizeBody(req.body);

    if (!isAllowedOrigin(origin)) {
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
          requestUserAgent
        }
      });

      return res.status(403).json({
        success: false,
        message: "Forbidden origin."
      });
    }

    const rateLimitResult = checkApiRateLimit({
      key: `security-log:${ip}`,
      limit: 20,
      windowMs: 5 * 60 * 1000,
      route: ROUTE
    });

    if (!rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Security log endpoint rate limited",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action: rateLimitResult.recommendedAction,
          remainingMs: rateLimitResult.remainingMs || 0,
          violations: rateLimitResult.violations || 0
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests.",
        action: rateLimitResult.recommendedAction,
        remainingMs: rateLimitResult.remainingMs || 0
      });
    }

    const abuseResult = trackApiAbuse({
      ip,
      sessionId: safeString(body.sessionId || "", 120),
      route: ROUTE,
      success: true
    });

    if (
      abuseResult.recommendedAction === "block" ||
      abuseResult.recommendedAction === "challenge"
    ) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Blocked suspicious client telemetry request",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          abuseScore: abuseResult.abuseScore,
          abuseLevel: abuseResult.level,
          reasons: abuseResult.reasons
        }
      });

      return res.status(403).json({
        success: false,
        message: "Suspicious request blocked."
      });
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
          requestUserAgent
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
        requestUserAgent,
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
