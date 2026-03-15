import { writeSecurityLog } from "./_security-log.js";
import { checkApiRateLimit } from "./_rate-limit.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";
import { analyzeBotBehavior } from "./_bot-detection.js";

const ROUTE = "/api/verify-turnstile";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_HOSTNAMES = new Set([
  "aethra-gules.vercel.app",
  "aethra-hb2h.vercel.app"
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

  return safeString(req.socket?.remoteAddress || "unknown", 100);
}

function isAllowedOrigin(origin) {
  return ALLOWED_ORIGINS.has(origin);
}

function normalizeHostname(hostname = "") {
  return safeString(hostname, 200).trim().toLowerCase();
}

function isExpectedHostname(hostname = "") {
  return ALLOWED_HOSTNAMES.has(normalizeHostname(hostname));
}

function safeErrorCodes(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.slice(0, 10).map((item) => safeString(item, 100));
}

function getFinalSecurityAction({ abuseAnalysis, botAnalysis }) {
  if (
    abuseAnalysis?.recommendedAction === "block" ||
    botAnalysis?.recommendedAction === "block"
  ) {
    return "block";
  }

  if (
    abuseAnalysis?.recommendedAction === "challenge" ||
    botAnalysis?.recommendedAction === "challenge"
  ) {
    return "challenge";
  }

  if (
    abuseAnalysis?.recommendedAction === "throttle" ||
    botAnalysis?.recommendedAction === "throttle"
  ) {
    return "throttle";
  }

  return "allow";
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
    const body = req.body && typeof req.body === "object" && !Array.isArray(req.body)
      ? req.body
      : {};

    const token = safeString(body.token || "", 5000);
    const sessionId = safeString(body.sessionId || "", 120);
    const behavior = body.behavior && typeof body.behavior === "object"
      ? body.behavior
      : {};

    const secret = process.env.TURNSTILE_SECRET_KEY;

    if (!isAllowedOrigin(origin)) {
      await writeSecurityLog({
        type: "forbidden_turnstile_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          origin,
          requestUserAgent
        }
      });

      return res.status(403).json({
        success: false,
        message: "Forbidden origin."
      });
    }

    const rateLimitResult = checkApiRateLimit({
      key: `verify-turnstile:${ip}`,
      limit: 10,
      windowMs: 60 * 1000,
      route: ROUTE
    });

    if (!rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "turnstile_rate_limited",
        level: "warning",
        message: "Rate limit exceeded on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action: rateLimitResult.recommendedAction,
          remainingMs: rateLimitResult.remainingMs,
          violations: rateLimitResult.violations || 0
        }
      });

      return res.status(429).json({
        success: false,
        message: "Too many requests. Please try again later.",
        action: rateLimitResult.recommendedAction,
        remainingMs: rateLimitResult.remainingMs || 0
      });
    }

    const abuseAnalysis = trackApiAbuse({
      ip,
      sessionId,
      route: ROUTE,
      success: Boolean(token)
    });

    const botAnalysis = analyzeBotBehavior(
      { ...behavior, route: ROUTE, sessionId },
      req
    );

    const finalAction = getFinalSecurityAction({
      abuseAnalysis,
      botAnalysis
    });

    if (finalAction === "block") {
      await writeSecurityLog({
        type: "blocked_suspicious_turnstile_request",
        level: "critical",
        message: "Blocked suspicious verify-turnstile request",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          abuseAnalysis,
          botAnalysis,
          finalAction
        }
      });

      return res.status(429).json({
        success: false,
        message: "Suspicious activity detected. Please try again later.",
        action: finalAction
      });
    }

    if (!token || !secret) {
      await writeSecurityLog({
        type: "turnstile_missing_token_or_secret",
        level: "error",
        message: "Missing token or server secret in verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          hasToken: Boolean(token),
          hasSecret: Boolean(secret)
        }
      });

      return res.status(400).json({
        success: false,
        message: "Missing token or secret."
      });
    }

    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          secret,
          response: token,
          remoteip: ip
        })
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      await writeSecurityLog({
        type: "turnstile_upstream_error",
        level: "error",
        message: "Turnstile upstream verification request failed",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          status: response.status
        }
      });

      return res.status(502).json({
        success: false,
        message: "Captcha verification service failed."
      });
    }

    if (!data.success) {
      await writeSecurityLog({
        type: "turnstile_verification_failed",
        level: "warning",
        message: "Turnstile verification failed",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          errorCodes: safeErrorCodes(data["error-codes"]),
          abuseLevel: abuseAnalysis.level,
          botLevel: botAnalysis.level
        }
      });

      return res.status(400).json({
        success: false,
        message: "Captcha verification failed."
      });
    }

    if (data.hostname && !isExpectedHostname(data.hostname)) {
      await writeSecurityLog({
        type: "turnstile_hostname_mismatch",
        level: "critical",
        message: "Turnstile token hostname did not match allowed hostnames",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          hostname: normalizeHostname(data.hostname)
        }
      });

      return res.status(400).json({
        success: false,
        message: "Captcha hostname validation failed."
      });
    }

    return res.status(200).json({
      success: true,
      action: finalAction === "allow" ? "allow" : finalAction
    });
  } catch (error) {
    console.error("Turnstile API error:", error);

    try {
      await writeSecurityLog({
        type: "turnstile_api_error",
        level: "error",
        message: "Unhandled server error in verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          error: safeString(error?.message || "Unknown error", 500)
        }
      });
    } catch (logError) {
      console.error("Security log write failed:", logError);
    }

    return res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
}
