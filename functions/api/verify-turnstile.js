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
const MAX_SESSION_ID_LENGTH = 120;

const ALLOWED_ORIGINS = new Set([
  "http://127.0.0.1:8080",
  "http://localhost:8080",
  "https://aethra-c46.pages.dev"
]);

const ALLOWED_HOSTNAMES = new Set([
  "127.0.0.1",
  "localhost",
  "aethra-c46.pages.dev"
]);

function normalizeOrigin(origin = "") {
  const raw = safeString(origin, 200).trim();
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
  const normalized = safeString(email, 200).trim().toLowerCase();
  if (!normalized) return "";
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized) ? normalized : "";
}

function isExpectedHostname(hostname = "") {
  return ALLOWED_HOSTNAMES.has(normalizeHostname(hostname));
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(normalizeOrigin(origin));
}

function safeErrorCodes(value) {
  if (!Array.isArray(value)) return [];

  return value
    .slice(0, 10)
    .map((item) => safeString(item, 100))
    .filter(Boolean);
}

function pickSecurityAction(security) {
  return safeString(
    security?.risk?.finalAction || security?.risk?.action || "allow",
    20
  ).toLowerCase();
}

function getTurnstileSecret(env) {
  return safeString(env?.TURNSTILE_SECRET_KEY || "", 5000).trim();
}

function getRequestContentLength(request) {
  const raw = request.headers.get("content-length");
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
}

function isJsonContentType(request) {
  const contentType = safeString(
    request.headers.get("content-type") || "",
    200
  ).toLowerCase();

  return contentType.startsWith("application/json");
}

function getRequestHost(request) {
  const hostHeader = safeString(request.headers.get("host") || "", 200).toLowerCase();
  return normalizeHostname(hostHeader.split(":")[0] || "");
}

function isRequestHostAllowed(request) {
  return isExpectedHostname(getRequestHost(request));
}

function getRefererOrigin(request) {
  const referer = safeString(request.headers.get("referer") || "", 500).trim();
  if (!referer) return "";

  try {
    return new URL(referer).origin.toLowerCase();
  } catch {
    return "";
  }
}

function getClientIp(request) {
  const cfIp = safeString(request.headers.get("cf-connecting-ip") || "", 100).trim();
  if (cfIp) return cfIp;

  const forwardedFor = safeString(request.headers.get("x-forwarded-for") || "", 300).trim();
  if (forwardedFor) {
    return safeString(forwardedFor.split(",")[0] || "", 100).trim();
  }

  return "0.0.0.0";
}

async function sha256Hex(input = "") {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function createVerificationFingerprint({ ip, token, origin, host }) {
  const raw = [
    safeString(ip, 100),
    safeString(token, 500),
    safeString(origin, 200),
    safeString(host, 200)
  ].join("|");

  return (await sha256Hex(raw)).slice(0, 32);
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

function buildCorsHeaders(origin = "") {
  const normalizedOrigin = normalizeOrigin(origin);
  const allowOrigin = isOriginAllowed(normalizedOrigin) ? normalizedOrigin : "null";

  return {
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    pragma: "no-cache",
    expires: "0",
    vary: "Origin",
    "content-type": "application/json; charset=utf-8"
  };
}

function jsonResponse(origin, payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: buildCorsHeaders(origin)
  });
}

function buildJsonError(origin, status, message, extra = {}) {
  return jsonResponse(
    origin,
    {
      success: false,
      message: safeString(message || "Request failed.", 300),
      ...extra
    },
    status
  );
}

function buildSecurityMetadata({
  actor,
  requestHost,
  refererOrigin,
  sessionId,
  fingerprint,
  security,
  clientContext,
  extra = {}
}) {
  return sanitizeMetadata({
    source: "server_enforced",
    origin: actor?.origin || "",
    refererOrigin,
    host: requestHost,
    requestUserAgent: actor?.userAgent || "",
    sessionId: actor?.sessionId || sessionId || "",
    fingerprint: fingerprint || "",
    risk: security?.risk,
    botResult: security?.signals?.botResult,
    abuseResult: security?.signals?.abuseResult,
    threatResult: security?.signals?.threatResult,
    clientContext,
    ...extra
  });
}

function createCloudflareRequestLike(context, body) {
  const request = context.request;
  const url = new URL(request.url);
  const ip = getClientIp(request);

  return {
    method: request.method,
    url: request.url,
    headers: {
      origin: request.headers.get("origin") || "",
      referer: request.headers.get("referer") || "",
      host: request.headers.get("host") || "",
      "content-type": request.headers.get("content-type") || "",
      "content-length": request.headers.get("content-length") || "",
      "user-agent": request.headers.get("user-agent") || "",
      "cf-connecting-ip": ip,
      "x-forwarded-for": ip
    },
    body,
    query: Object.fromEntries(url.searchParams.entries()),
    socket: {
      remoteAddress: ip
    },
    cf: request.cf || {},
    ip
  };
}

async function writeBlockedOriginLog({
  actor,
  requestHost,
  refererOrigin,
  sessionId
}) {
  await writeSecurityLog({
    type: "forbidden_turnstile_origin",
    level: "warning",
    message: "Blocked request from forbidden origin on verify-turnstile API",
    ip: actor.ip,
    route: ROUTE,
    metadata: buildSecurityMetadata({
      actor,
      requestHost,
      refererOrigin,
      sessionId
    })
  });
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("origin") || "";

  return new Response(null, {
    status: 204,
    headers: buildCorsHeaders(origin)
  });
}

export async function onRequestPost(context) {
  const request = context.request;
  const origin = request.headers.get("origin") || "";
  const requestHost = getRequestHost(request);
  const refererOrigin = getRefererOrigin(request);

  if (!isJsonContentType(request)) {
    return buildJsonError(origin, 415, "Unsupported content type.");
  }

  if (getRequestContentLength(request) > MAX_CONTENT_LENGTH_BYTES) {
    return buildJsonError(origin, 413, "Request body too large.");
  }

  try {
    let rawBody;
    try {
      rawBody = await request.json();
    } catch {
      return buildJsonError(origin, 400, "Invalid JSON body.");
    }

    const body = sanitizeBody(rawBody, MAX_BODY_KEYS);
    const token = safeString(body?.token || "", MAX_TOKEN_LENGTH).trim();
    const behavior = getClientBehavior(body);
    const clientContext = sanitizeClientContext(body?.context);
    const email = normalizeEmail(body?.email || "");
    const sessionId = safeString(body?.sessionId || "", MAX_SESSION_ID_LENGTH).trim();

    const reqLike = createCloudflareRequestLike(context, body);

    const actor = createActorContext({
      req: reqLike,
      body,
      behavior,
      route: ROUTE
    });

    if (!isRequestHostAllowed(request)) {
      await writeSecurityLog({
        type: "forbidden_turnstile_host",
        level: "critical",
        message: "Blocked request to verify-turnstile API on unexpected host",
        ip: actor.ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId
        })
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Forbidden host.", { action: "block" }),
        403
      );
    }

    if (!isOriginAllowed(actor.origin)) {
      await writeBlockedOriginLog({
        actor,
        requestHost,
        refererOrigin,
        sessionId
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Forbidden origin.", { action: "block" }),
        403
      );
    }

    const security = await runSecurityOrchestrator({
      req: reqLike,
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

    const ip = security?.actor?.ip || actor.ip;
    const securityAction = pickSecurityAction(security);
    const secret = getTurnstileSecret(context.env);
    const resolvedSessionId = actor.sessionId || sessionId;

    const verificationFingerprint = await createVerificationFingerprint({
      ip,
      token,
      origin: actor.origin,
      host: requestHost
    });

    if (
      security?.signals?.rateLimitResult &&
      !security.signals.rateLimitResult.allowed
    ) {
      await writeSecurityLog({
        type: "turnstile_rate_limited",
        level: "warning",
        message: "Rate limit exceeded on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext,
          extra: {
            action: security.signals.rateLimitResult.recommendedAction,
            remainingMs: security.signals.rateLimitResult.remainingMs || 0,
            violations: security.signals.rateLimitResult.violations || 0,
            riskScore: security?.risk?.riskScore,
            riskLevel: security?.risk?.level
          }
        })
      });

      return buildJsonError(
        origin,
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
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext
        })
      });

      return jsonResponse(
        origin,
        buildBlockedResponse(
          "Suspicious activity detected. Please try again later.",
          { action: "block" }
        ),
        429
      );
    }

    if (securityAction === "challenge" || securityAction === "throttle") {
      await writeSecurityLog({
        type: "temporary_turnstile_security_challenge",
        level: "warning",
        message: "Suspicious behavior detected on verify-turnstile API",
        ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext
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
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext,
          extra: {
            hasToken: Boolean(token),
            hasSecret: Boolean(secret),
            riskScore: security?.risk?.riskScore
          }
        })
      });

      return buildJsonError(origin, 400, "Missing token or secret.");
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TURNSTILE_TIMEOUT_MS);

    let upstreamResponse;
    let data = {};

    try {
      upstreamResponse = await fetch(TURNSTILE_VERIFY_URL, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          secret,
          response: token,
          remoteip: ip
        }),
        signal: controller.signal
      });

      data = await upstreamResponse.json().catch(() => ({}));
    } catch (error) {
      const isAbort = error?.name === "AbortError";

      await writeSecurityLog({
        type: isAbort ? "turnstile_timeout" : "turnstile_upstream_error",
        level: "error",
        message: isAbort
          ? "Turnstile verification request timed out"
          : "Turnstile verification request failed",
        ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext,
          extra: {
            error: safeString(error?.message || "Unknown upstream error", 300),
            riskScore: security?.risk?.riskScore
          }
        })
      });

      return buildJsonError(origin, 502, "Captcha verification service failed.");
    } finally {
      clearTimeout(timeoutId);
    }

    if (!upstreamResponse.ok) {
      await writeSecurityLog({
        type: "turnstile_upstream_bad_status",
        level: "error",
        message: "Turnstile upstream verification returned bad status",
        ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext,
          extra: {
            status: upstreamResponse.status,
            riskScore: security?.risk?.riskScore
          }
        })
      });

      return buildJsonError(origin, 502, "Captcha verification service failed.");
    }

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      await writeSecurityLog({
        type: "turnstile_invalid_upstream_payload",
        level: "error",
        message: "Turnstile returned invalid payload",
        ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext,
          extra: {
            riskScore: security?.risk?.riskScore
          }
        })
      });

      return buildJsonError(origin, 502, "Captcha verification service failed.");
    }

    if (data.success !== true) {
      await writeSecurityLog({
        type: "turnstile_verification_failed",
        level: "warning",
        message: "Turnstile verification failed",
        ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext,
          extra: {
            errorCodes: safeErrorCodes(data["error-codes"]),
            hostname: normalizeHostname(data.hostname || ""),
            abuseLevel: security?.signals?.abuseResult?.level || "low",
            botLevel: security?.signals?.botResult?.level || "low",
            threatLevel: security?.signals?.threatResult?.level || "low",
            riskLevel: security?.risk?.level
          }
        })
      });

      return buildJsonError(origin, 400, "Captcha verification failed.");
    }

    if (data.hostname && !isExpectedHostname(data.hostname)) {
      await writeSecurityLog({
        type: "turnstile_hostname_mismatch",
        level: "critical",
        message: "Turnstile token hostname did not match allowed hostnames",
        ip,
        route: ROUTE,
        metadata: buildSecurityMetadata({
          actor,
          requestHost,
          refererOrigin,
          sessionId: resolvedSessionId,
          fingerprint: verificationFingerprint,
          security,
          clientContext,
          extra: {
            hostname: normalizeHostname(data.hostname),
            riskScore: security?.risk?.riskScore
          }
        })
      });

      return buildJsonError(origin, 400, "Captcha hostname validation failed.");
    }

    return jsonResponse(origin, {
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

    return buildJsonError(origin, 500, "Server error.");
  }
}

export async function onRequest(context) {
  const method = context.request.method;

  if (method === "OPTIONS") {
    return onRequestOptions(context);
  }

  if (method === "POST") {
    return onRequestPost(context);
  }

  return jsonResponse(
    context.request.headers.get("origin") || "",
    buildMethodNotAllowedResponse(),
    405
  );
}
