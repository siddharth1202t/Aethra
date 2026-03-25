import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import {
  safeString,
  safeNumber,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse,
  buildDeniedResponse,
  buildChallengeResponse,
  buildThrottleResponse,
  runRouteSecurity
} from "./_api-security.js";
import { validateFreshRequest } from "./_request-freshness.js";

const ROUTE = "/api/security-log";
const PRIMARY_DOMAIN = "aethra-c46.pages.dev";

const MAX_BODY_KEYS = 14;
const MAX_EVENT_AGE_MS = 2 * 60 * 1000;
const EVENT_FUTURE_TOLERANCE_MS = 15 * 1000;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

const ALLOWED_CLIENT_EVENT_TYPES = new Set([
  "client_error",
  "auth_ui_error",
  "turnstile_ui_error",
  "frontend_security_signal",
  "session_client_warning",
  "suspicious_client_state"
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
  return safeString(hostname || "", 200).trim().toLowerCase();
}

function normalizeIp(value = "") {
  return (
    safeString(value || "unknown", 100)
      .replace(/[^a-fA-F0-9:.,]/g, "")
      .slice(0, 100) || "unknown"
  );
}

function getRequestHost(request) {
  return normalizeHostname((request.headers.get("host") || "").split(":")[0]);
}

function getClientIp(request) {
  const cfIp = request.headers.get("cf-connecting-ip");
  if (cfIp) return normalizeIp(cfIp.trim());

  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return normalizeIp(forwarded.split(",")[0].trim());

  const realIp = request.headers.get("x-real-ip");
  if (realIp) return normalizeIp(realIp.trim());

  return "unknown";
}

function isLocal(origin) {
  return (
    origin.startsWith("http://localhost") ||
    origin.startsWith("http://127.0.0.1")
  );
}

function isPagesDev(value) {
  return safeString(value || "", 300).toLowerCase().endsWith(".pages.dev");
}

function isOriginAllowed(origin = "") {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;

  if (isLocal(normalized)) return true;
  if (normalized === `https://${PRIMARY_DOMAIN}`) return true;
  if (isPagesDev(normalized)) return true;

  return false;
}

function isExpectedHostname(hostname = "") {
  const normalized = normalizeHostname(hostname);
  if (!normalized) return false;

  if (normalized === "localhost" || normalized === "127.0.0.1") return true;
  if (normalized === PRIMARY_DOMAIN) return true;
  if (isPagesDev(normalized)) return true;

  return false;
}

function normalizeClientEventType(type = "") {
  const normalized = safeString(type || "", 50).toLowerCase();
  return ALLOWED_CLIENT_EVENT_TYPES.has(normalized)
    ? normalized
    : "frontend_security_signal";
}

function buildTelemetryNonceScope(type = "") {
  return `security-log:${safeString(type, 50)}`;
}

function buildHeaders(origin = "") {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    "pragma": "no-cache",
    "expires": "0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer"
  };

  if (origin && isOriginAllowed(origin)) {
    headers["access-control-allow-origin"] = normalizeOrigin(origin);
    headers["access-control-allow-methods"] = "POST, OPTIONS";
    headers["access-control-allow-headers"] = "Content-Type";
    headers["vary"] = "Origin";
  }

  return headers;
}

function jsonResponse(origin, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: buildHeaders(origin)
  });
}

async function logRouteEvent({
  env,
  type,
  level,
  message,
  actor,
  request,
  metadata = {}
}) {
  await writeSecurityLog({
    env,
    type,
    level,
    message,
    ip: actor?.ip || getClientIp(request),
    route: ROUTE,
    userId: actor?.userId || null,
    sessionId: actor?.sessionId || null,
    metadata: {
      actorKey: actor?.actorKey || null,
      routeKey: actor?.routeKey || null,
      host: getRequestHost(request),
      origin: normalizeOrigin(request.headers.get("origin") || ""),
      method: request.method,
      ...metadata
    }
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  const origin = normalizeOrigin(request.headers.get("origin") || "");
  const host = getRequestHost(request);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: buildHeaders(origin)
    });
  }

  if (request.method !== "POST") {
    return jsonResponse(origin, buildMethodNotAllowedResponse(), 405);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return jsonResponse(
      origin,
      buildDeniedResponse("Unsupported content type.", { action: "deny" }),
      415
    );
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return jsonResponse(
      origin,
      buildDeniedResponse("Request body too large.", { action: "deny" }),
      413
    );
  }

  let ip = "unknown";

  try {
    const bodyRaw = await request.json();
    const body = sanitizeBody(bodyRaw, MAX_BODY_KEYS);

    const actor = createActorContext({
      req: request,
      body,
      route: ROUTE
    });

    ip = actor.ip || getClientIp(request);

    if (!isOriginAllowed(origin)) {
      await logRouteEvent({
        env,
        type: "security_log_forbidden_origin",
        level: "warning",
        message: "Blocked telemetry request from forbidden origin",
        actor,
        request,
        metadata: {
          blockedReason: "forbidden_origin",
          origin
        }
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Forbidden origin.", { action: "block" }),
        403
      );
    }

    if (!isExpectedHostname(host)) {
      await logRouteEvent({
        env,
        type: "security_log_forbidden_host",
        level: "warning",
        message: "Blocked telemetry request from forbidden host",
        actor,
        request,
        metadata: {
          blockedReason: "forbidden_host",
          host
        }
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Forbidden host.", { action: "block" }),
        403
      );
    }

    const security = await runRouteSecurity({
      env,
      req: request,
      route: ROUTE,
      allowedOrigins: null,
      body,
      sessionId: safeString(body.sessionId || "", 120),
      behavior: {
        userAgent: safeString(body.userAgent || "", 500),
        route: ROUTE
      },
      abuseSuccess: true,
      containmentConfig: {
        isWriteAction: true,
        actionType: "security_log",
        routeSensitivity: "critical"
      },
      rateLimitConfig: {
        key: `security-log:${actor.actorKey}`,
        limit: 20,
        windowMs: 60 * 1000
      }
    });

    const finalAction = safeString(
      security?.finalAction || security?.risk?.finalAction || "allow",
      20
    ).toLowerCase();

    if (security?.rateLimitResult && !security.rateLimitResult.allowed) {
      await logRouteEvent({
        env,
        type: "security_log_rate_limited",
        level: "warning",
        message: "Security log endpoint rate limited",
        actor,
        request,
        metadata: {
          action: security.rateLimitResult.recommendedAction || "throttle",
          degraded: security.rateLimitResult.degraded === true
        }
      });

      return jsonResponse(
        origin,
        buildThrottleResponse("Too many requests.", { action: "throttle" }),
        429
      );
    }

    if (finalAction === "block") {
      await logRouteEvent({
        env,
        type: "security_log_blocked",
        level: "warning",
        message: "Suspicious telemetry request blocked",
        actor,
        request,
        metadata: {
          finalAction,
          containmentAction:
            security?.containmentAction ||
            security?.risk?.finalContainmentAction ||
            "none",
          combinedRisk: safeNumber(
            security?.combinedRisk || security?.risk?.riskScore || 0,
            0
          )
        }
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Suspicious request blocked.", {
          action: "block"
        }),
        403
      );
    }

    if (finalAction === "challenge") {
      await logRouteEvent({
        env,
        type: "security_log_challenged",
        level: "warning",
        message: "Telemetry request requires verification",
        actor,
        request,
        metadata: {
          finalAction,
          containmentAction:
            security?.containmentAction ||
            security?.risk?.finalContainmentAction ||
            "none",
          combinedRisk: safeNumber(
            security?.combinedRisk || security?.risk?.riskScore || 0,
            0
          )
        }
      });

      return jsonResponse(
        origin,
        buildChallengeResponse("Verification required.", {
          action: "challenge"
        }),
        403
      );
    }

    const clientEventType = normalizeClientEventType(body.type);
    const message = safeString(body.message, 500);

    const freshRequestResult = await validateFreshRequest({
      env,
      requestAt: body.eventAt,
      nonce: safeString(body.nonce, 200),
      scope: buildTelemetryNonceScope(clientEventType),
      requireNonce: Boolean(body.nonce),
      requireNonceStorage: true,
      maxAgeMs: MAX_EVENT_AGE_MS,
      futureToleranceMs: EVENT_FUTURE_TOLERANCE_MS,
      nonceTtlMs: 10 * 60 * 1000
    });

    if (!freshRequestResult.ok) {
      await logRouteEvent({
        env,
        type: "security_log_rejected_freshness",
        level: "warning",
        message: "Rejected replayed or stale telemetry request",
        actor,
        request,
        metadata: {
          freshnessCode: safeString(freshRequestResult.code, 100),
          degraded: freshRequestResult.degraded === true
        }
      });

      return jsonResponse(
        origin,
        buildDeniedResponse("Invalid telemetry request.", {
          action: "deny"
        }),
        400
      );
    }

    await writeSecurityLog({
      env,
      type: "client_security_telemetry",
      level: "info",
      message: message || "Client telemetry received",
      ip,
      route: ROUTE,
      userId: actor?.userId || null,
      sessionId: actor?.sessionId || null,
      metadata: sanitizeMetadata({
        source: "client_untrusted",
        clientEventType,
        eventAt: safeNumber(body.eventAt, 0),
        receivedAt: Date.now(),
        ageMs: safeNumber(freshRequestResult.ageMs, 0),
        degraded: freshRequestResult.degraded === true,
        clientAssertedSessionId: safeString(body.sessionId || "", 120),
        actorKey: actor?.actorKey || null,
        routeKey: actor?.routeKey || null,
        host,
        origin
      })
    });

    return jsonResponse(origin, {
      success: true,
      action: "allow"
    });
  } catch (error) {
    console.error("Security log API error:", error);

    try {
      await writeSecurityLog({
        env,
        type: "security_log_api_error",
        level: "error",
        message: "Unhandled error in security-log API",
        ip,
        route: ROUTE,
        metadata: {
          error: safeString(error?.message || "Unknown error", 500)
        }
      });
    } catch {}

    return jsonResponse(
      origin,
      buildDeniedResponse("Internal server error.", {
        action: "deny"
      }),
      500
    );
  }
}
