import { writeSecurityLog } from "./_security-log.js";
import { checkApiRateLimit } from "./_rate-limit.js";

const ROUTE = "/api/security-log";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_TYPES = new Set([
  "unknown",
  "captcha_missing",
  "login_success",
  "login_failed",
  "google_login_success",
  "google_login_failed",
  "google_login_redirect_started",
  "signup_success",
  "signup_failed",
  "google_signup_success",
  "google_signup_failed",
  "google_signup_redirect_started",
  "password_reset_requested",
  "password_reset_failed",
  "client_security_event",
  "page_error",
  "suspicious_client_behavior"
]);

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error",
  "critical"
]);

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
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

  return req.socket?.remoteAddress || "unknown";
}

function isAllowedOrigin(origin) {
  return ALLOWED_ORIGINS.has(origin);
}

function safeType(type) {
  const normalized = safeString(type || "unknown", 50);
  return ALLOWED_TYPES.has(normalized) ? normalized : "client_security_event";
}

function safeLevel(level) {
  const normalized = safeString(level || "warning", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "warning";
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
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
    const entries = Object.entries(value).slice(0, 25);

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

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed."
    });
  }

  try {
    const origin = safeString(req.headers.origin || "", 200);
    const ip = getClientIp(req);
    const body = req.body && typeof req.body === "object" ? req.body : {};

    if (!isAllowedOrigin(origin)) {
      await writeSecurityLog({
        type: "client_security_event",
        level: "warning",
        message: "Blocked client security log request from forbidden origin",
        ip,
        route: ROUTE,
        metadata: {
          origin
        }
      });

      return res.status(403).json({
        success: false,
        message: "Forbidden origin."
      });
    }

    const rateLimitResult = checkApiRateLimit({
      key: `security-log:${ip}`,
      limit: 30,
      windowMs: 5 * 60 * 1000
    });

    if (!rateLimitResult.allowed) {
      return res.status(429).json({
        success: false,
        message: "Too many requests.",
        remainingMs: rateLimitResult.remainingMs || 0
      });
    }

    const type = safeType(body.type);
    const level = safeLevel(body.level);
    const message = safeString(body.message || "", 500);
    const email = safeString(body.email || "", 200);
    const userId = safeString(body.userId || "", 128);
    const metadata = sanitizeMetadata(body.metadata || {});
    const client = sanitizeClient(body.client || {});

    await writeSecurityLog({
      type,
      level,
      message,
      email,
      userId,
      ip,
      route: ROUTE,
      metadata: {
        ...metadata,
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
        ip: getClientIp(req),
        route: ROUTE,
        metadata: {
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
