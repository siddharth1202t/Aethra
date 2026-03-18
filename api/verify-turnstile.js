import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import {
  safeString,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse
} from "./_api-security.js";

const ROUTE = "/api/verify-turnstile";
const TURNSTILE_VERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TURNSTILE_TIMEOUT_MS = 8000;

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

const ALLOWED_HOSTNAMES = new Set([
  "aethra-gules.vercel.app",
  "aethra-hb2h.vercel.app"
]);

function setNoStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
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

function normalizeHostname(hostname = "") {
  return safeString(hostname, 200).trim().toLowerCase();
}

function isExpectedHostname(hostname = "") {
  return ALLOWED_HOSTNAMES.has(normalizeHostname(hostname));
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(normalizeOrigin(origin));
}

function safeErrorCodes(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .slice(0, 10)
    .map((item) => safeString(item, 100))
    .filter(Boolean);
}

function createTimeoutSignal(timeoutMs = TURNSTILE_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  return { controller, timeout };
}

function pickSecurityAction(security) {
  return safeString(
    security?.risk?.finalAction || security?.risk?.action || "allow",
    20
  ).toLowerCase();
}

function getTurnstileSecret() {
  return safeString(process.env.TURNSTILE_SECRET_KEY || "", 5000).trim();
}

function buildJsonError(res, status, message, extra = {}) {
  return res.status(status).json({
    success: false,
    message: safeString(message || "Request failed.", 300),
    ...extra
  });
}

export default async function handler(req, res) {
  setNoStore(res);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json(buildMethodNotAllowedResponse());
  }

  try {
    const body = sanitizeBody(req.body, 20);

    const token = safeString(body.token || "", 5000).trim();
    const behavior =
      body.behavior &&
      typeof body.behavior === "object" &&
      !Array.isArray(body.behavior)
        ? body.behavior
        : {};

    const actor = createActorContext({
      req,
      body,
      behavior,
      route: ROUTE
    });

    if (!isOriginAllowed(actor.origin)) {
      await writeSecurityLog({
        type: "forbidden_turnstile_origin",
        level: "warning",
        message: "Blocked request from forbidden origin on verify-turnstile API",
        ip: actor.ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          origin: actor.origin,
          requestUserAgent: actor.userAgent
        }
      });

      return res.status(403).json(
        buildBlockedResponse("Forbidden origin.", { action: "block" })
      );
    }

    const security = await runSecurityOrchestrator({
      req,
      body,
      behavior,
      route: ROUTE,
      context: {
        ip: actor.ip,
        sessionId: actor.sessionId,
        userId: actor.userId
      },
      rateLimitConfig: {
        key: `verify-turnstile:${actor.ip}`,
        limit: 10,
        windowMs: 60 * 1000
      },
      abuseSuccess: Boolean(token)
    });

    const ip = security.actor.ip;
    const securityAction = pickSecurityAction(security);
    const secret = getTurnstileSecret();

    if (security.signals.rateLimitResult && !security.signals.rateLimitResult.allowed) {
      await writeSecurityLog({
        type: "turnstile_rate_limited",
        level: "warning",
        message: "Rate limit exceeded on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          action: security.signals.rateLimitResult.recommendedAction,
          remainingMs: security.signals.rateLimitResult.remainingMs || 0,
          violations: security.signals.rateLimitResult.violations || 0,
          riskScore: security.risk.riskScore,
          riskLevel: security.risk.level
        }
      });

      return buildJsonError(
        res,
        429,
        "Too many requests. Please try again later.",
        {
          action: security.signals.rateLimitResult.recommendedAction,
          remainingMs: security.signals.rateLimitResult.remainingMs || 0
        }
      );
    }

    if (securityAction === "block") {
      await writeSecurityLog({
        type: "blocked_suspicious_turnstile_request",
        level: "critical",
        message: "Blocked suspicious verify-turnstile request",
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          risk: security.risk,
          botResult: security.signals.botResult,
          abuseResult: security.signals.abuseResult,
          threatResult: security.signals.threatResult
        })
      });

      return res.status(429).json(
        buildBlockedResponse(
          "Suspicious activity detected. Please try again later.",
          { action: "block" }
        )
      );
    }

    if (securityAction === "challenge" || securityAction === "throttle") {
      await writeSecurityLog({
        type: "temporary_turnstile_security_challenge",
        level: "warning",
        message: "Suspicious behavior detected on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: sanitizeMetadata({
          source: "server_enforced",
          risk: security.risk,
          botResult: security.signals.botResult,
          abuseResult: security.signals.abuseResult,
          threatResult: security.signals.threatResult
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
          hasSecret: Boolean(secret),
          riskScore: security.risk.riskScore
        }
      });

      return buildJsonError(res, 400, "Missing token or secret.");
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
          error: safeString(error?.message || "Unknown upstream error", 300),
          riskScore: security.risk.riskScore
        }
      });

      return buildJsonError(
        res,
        502,
        "Captcha verification service failed."
      );
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
          status: response.status,
          riskScore: security.risk.riskScore
        }
      });

      return buildJsonError(
        res,
        502,
        "Captcha verification service failed."
      );
    }

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      await writeSecurityLog({
        type: "turnstile_invalid_upstream_payload",
        level: "error",
        message: "Turnstile returned invalid payload",
        ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          riskScore: security.risk.riskScore
        }
      });

      return buildJsonError(
        res,
        502,
        "Captcha verification service failed."
      );
    }

    if (data.success !== true) {
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
          abuseLevel: security.signals.abuseResult?.level || "low",
          botLevel: security.signals.botResult?.level || "low",
          threatLevel: security.signals.threatResult?.level || "low",
          riskLevel: security.risk.level
        }
      });

      return buildJsonError(res, 400, "Captcha verification failed.");
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
          hostname: normalizeHostname(data.hostname),
          riskScore: security.risk.riskScore
        }
      });

      return buildJsonError(res, 400, "Captcha hostname validation failed.");
    }

    return res.status(200).json({
      success: true,
      action: securityAction === "allow" ? "allow" : securityAction
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

    return buildJsonError(res, 500, "Server error.");
  }
}
