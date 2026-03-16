import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse,
  runRouteSecurity
} from "./_api-security.js";

const ROUTE = "/api/verify-turnstile";
const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TURNSTILE_TIMEOUT_MS = 8000;

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_HOSTNAMES = new Set([
  "aethra-gules.vercel.app",
  "aethra-hb2h.vercel.app"
]);

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

function createTimeoutSignal(timeoutMs = TURNSTILE_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  return { controller, timeout };
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json(buildMethodNotAllowedResponse());
  }

  try {
    const body = sanitizeBody(req.body, 20);

    const token = safeString(body.token || "", 5000);
    const sessionId = safeString(body.sessionId || "", 120);
    const behavior =
      body.behavior && typeof body.behavior === "object" && !Array.isArray(body.behavior)
        ? body.behavior
        : {};

    const security = runRouteSecurity({
      req,
      route: ROUTE,
      allowedOrigins: ALLOWED_ORIGINS,
      rateLimit: {
        key: `verify-turnstile:${safeString(
          req?.headers?.["x-forwarded-for"] ||
          req?.headers?.["x-real-ip"] ||
          req?.socket?.remoteAddress ||
          "unknown",
          100
        )}`,
        limit: 10,
        windowMs: 60 * 1000
      },
      body,
      behavior,
      sessionId,
      abuseSuccess: Boolean(token)
    });

    const ip = security.ip;
    const origin = security.origin;
    const secret = process.env.TURNSTILE_SECRET_KEY;

    if (!security.originAllowed) {
      await writeSecurityLog({
        type: "forbidden_turnstile_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          origin,
          requestUserAgent: security.requestUserAgent
        }
      });

      return res.status(403).json(
        buildBlockedResponse("Forbidden origin.", { action: "block" })
      );
    }

    if (security.rateLimitResult && !security.rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "turnstile_rate_limited",
        level: "warning",
        message: "Rate limit exceeded on verify-turnstile API",
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
        message: "Too many requests. Please try again later.",
        action: security.rateLimitResult.recommendedAction,
        remainingMs: security.rateLimitResult.remainingMs || 0
      });
    }

    if (security.finalAction === "block") {
      await writeSecurityLog({
        type: "blocked_suspicious_turnstile_request",
        level: "critical",
        message: "Blocked suspicious verify-turnstile request",
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          botAnalysis: security.botAnalysis,
          abuseAnalysis: security.abuseAnalysis,
          combinedRisk: security.combinedRisk,
          finalAction: security.finalAction
        })
      });

      return res.status(429).json(
        buildBlockedResponse("Suspicious activity detected. Please try again later.", {
          action: security.finalAction
        })
      );
    }

    if (security.finalAction === "challenge" || security.finalAction === "throttle") {
      await writeSecurityLog({
        type: "temporary_turnstile_security_challenge",
        level: "warning",
        message: "Suspicious behavior detected on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          botAnalysis: security.botAnalysis,
          abuseAnalysis: security.abuseAnalysis,
          combinedRisk: security.combinedRisk,
          finalAction: security.finalAction
        })
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

    const { controller, timeout } = createTimeoutSignal();

    let response;
    let data = {};

    try {
      response = await fetch(TURNSTILE_VERIFY_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          secret,
          response: token,
          remoteip: ip
        }),
        signal: controller.signal
      });

      data = await response.json().catch(() => ({}));
    } catch (error) {
      clearTimeout(timeout);

      const isAbort = error?.name === "AbortError";

      await writeSecurityLog({
        type: isAbort ? "turnstile_timeout" : "turnstile_upstream_error",
        level: "error",
        message: isAbort
          ? "Turnstile verification request timed out"
          : "Turnstile verification request failed",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          error: safeString(error?.message || "Unknown upstream error", 300)
        }
      });

      return res.status(502).json({
        success: false,
        message: "Captcha verification service failed."
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      await writeSecurityLog({
        type: "turnstile_upstream_bad_status",
        level: "error",
        message: "Turnstile upstream verification returned bad status",
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

    if (!data || typeof data !== "object") {
      await writeSecurityLog({
        type: "turnstile_invalid_upstream_payload",
        level: "error",
        message: "Turnstile returned invalid payload",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced"
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
          hostname: normalizeHostname(data.hostname || ""),
          abuseLevel: security.abuseAnalysis?.level || "low",
          botLevel: security.botAnalysis?.level || "low"
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
      action: security.finalAction === "allow" ? "allow" : security.finalAction
    });
  } catch (error) {
    console.error("Turnstile API error:", error);

    try {
      await writeSecurityLog({
        type: "turnstile_api_error",
        level: "error",
        message: "Unhandled server error in verify-turnstile API",
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
