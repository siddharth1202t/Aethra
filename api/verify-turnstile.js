import crypto from "node:crypto";

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
const MAX_BODY_KEYS = 25;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;
const MAX_TOKEN_LENGTH = 5000;

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

function setNoStore(res) {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
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

function normalizeEmail(email = "") {
  const normalized = safeString(email || "", 200).trim().toLowerCase();
  if (!normalized) {
    return "";
  }

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized) ? normalized : "";
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

function getRequestContentLength(req) {
  const raw = req?.headers?.["content-length"];
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function isJsonContentType(req) {
  const contentType = safeString(req?.headers?.["content-type"] || "", 200)
    .toLowerCase();
  return contentType.startsWith("application/json");
}

function getRequestHost(req) {
  const hostHeader = safeString(req?.headers?.host || "", 200).toLowerCase();
  return normalizeHostname(hostHeader.split(":")[0] || "");
}

function isRequestHostAllowed(req) {
  return isExpectedHostname(getRequestHost(req));
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

function createVerificationFingerprint({ ip, token, origin, host }) {
  return crypto
    .createHash("sha256")
    .update(
      [
        safeString(ip, 100),
        safeString(token, 500),
        safeString(origin, 200),
        safeString(host, 200)
      ].join("|")
    )
    .digest("hex")
    .slice(0, 32);
}

function sanitizeClientContext(context) {
  if (!context || typeof context !== "object" || Array.isArray(context)) {
    return {};
  }

  return sanitizeMetadata({
    language: safeString(context.language || "", 50),
    platform: safeString(context.platform || "", 100),
    timezone: safeString(context.timezone || "", 100),
    webdriver: context.webdriver === true
  });
}

function getClientBehavior(body) {
  if (
    body?.behavior &&
    typeof body.behavior === "object" &&
    !Array.isArray(body.behavior)
  ) {
    return body.behavior;
  }

  return {};
}

async function logAndBlockOrigin({
  actor,
  ip,
  requestHost,
  refererOrigin,
  sessionId
}) {
  await writeSecurityLog({
    type: "forbidden_turnstile_origin",
    level: "warning",
    message: "Blocked request from forbidden origin on verify-turnstile API",
    ip,
    route: ROUTE,
    metadata: {
      source: "server_enforced",
      origin: actor.origin,
      refererOrigin,
      host: requestHost,
      requestUserAgent: actor.userAgent,
      sessionId
    }
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

  if (!isJsonContentType(req)) {
    return buildJsonError(res, 415, "Unsupported content type.");
  }

  if (getRequestContentLength(req) > MAX_CONTENT_LENGTH_BYTES) {
    return buildJsonError(res, 413, "Request body too large.");
  }

  try {
    const body = sanitizeBody(req.body, MAX_BODY_KEYS);
    const token = safeString(body?.token || "", MAX_TOKEN_LENGTH).trim();
    const behavior = getClientBehavior(body);
    const clientContext = sanitizeClientContext(body?.context);
    const email = normalizeEmail(body?.email || "");
    const sessionId = safeString(body?.sessionId || "", 120);

    const actor = createActorContext({
      req,
      body,
      behavior,
      route: ROUTE
    });

    const requestHost = getRequestHost(req);
    const refererOrigin = getRefererOrigin(req);

    if (!isRequestHostAllowed(req)) {
      await writeSecurityLog({
        type: "forbidden_turnstile_host",
        level: "critical",
        message: "Blocked request to verify-turnstile API on unexpected host",
        ip: actor.ip,
        route: ROUTE,
        metadata: {
          source: "server_enforced",
          host: requestHost,
          origin: actor.origin,
          refererOrigin,
          sessionId
        }
      });

      return res.status(403).json(
        buildBlockedResponse("Forbidden host.", { action: "block" })
      );
    }

    if (!isOriginAllowed(actor.origin)) {
      await logAndBlockOrigin({
        actor,
        ip: actor.ip,
        requestHost,
        refererOrigin,
        sessionId
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
        sessionId: actor.sessionId || sessionId,
        userId: actor.userId,
        email
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
    const resolvedSessionId = actor.sessionId || sessionId;

    const verificationFingerprint = createVerificationFingerprint({
      ip,
      token,
      origin: actor.origin,
      host: requestHost
    });

    if (
      security.signals.rateLimitResult &&
      !security.signals.rateLimitResult.allowed
    ) {
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
          riskLevel: security.risk.level,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          threatResult: security.signals.threatResult,
          clientContext,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          threatResult: security.signals.threatResult,
          clientContext,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          riskScore: security.risk.riskScore,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          riskScore: security.risk.riskScore,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          riskScore: security.risk.riskScore,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          riskScore: security.risk.riskScore,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          riskLevel: security.risk.level,
          clientContext,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
          riskScore: security.risk.riskScore,
          fingerprint: verificationFingerprint,
          sessionId: resolvedSessionId
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
