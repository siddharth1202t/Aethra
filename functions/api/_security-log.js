import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  safeNumber,
  sanitizeBody,
  sanitizeMetadata,
  buildBlockedResponse,
  buildMethodNotAllowedResponse,
  runRouteSecurity
} from "./_api-security.js";

import { validateFreshRequest } from "./_request-freshness.js";

const ROUTE = "/api/security-log";

const ALLOWED_ORIGINS = new Set([
  "http://127.0.0.1:8080",
  "http://localhost:8080",
  "https://aethra-c46.pages.dev"
]);

const MAX_BODY_KEYS = 14;
const MAX_EVENT_AGE_MS = 2 * 60 * 1000;
const EVENT_FUTURE_TOLERANCE_MS = 15 * 1000;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control":
        "no-store, no-cache, must-revalidate, proxy-revalidate",
      pragma: "no-cache",
      expires: "0"
    }
  });
}

function normalizeOrigin(origin = "") {
  const raw = safeString(origin, 200).trim();
  if (!raw) return "";

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(normalizeOrigin(origin));
}

function buildTelemetryNonceScope(type = "") {
  return `security-log:${safeString(type, 50)}`;
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  if (request.method !== "POST") {
    return jsonResponse(buildMethodNotAllowedResponse(), 405);
  }

  const contentType = request.headers.get("content-type") || "";

  if (!contentType.startsWith("application/json")) {
    return jsonResponse(
      {
        success: false,
        message: "Unsupported content type."
      },
      415
    );
  }

  const contentLength = Number(request.headers.get("content-length") || 0);

  if (contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return jsonResponse(
      {
        success: false,
        message: "Request body too large."
      },
      413
    );
  }

  let ip = "unknown";

  try {
    const bodyRaw = await request.json();
    const body = sanitizeBody(bodyRaw, MAX_BODY_KEYS);

    const origin = normalizeOrigin(request.headers.get("origin") || "");

    if (!isOriginAllowed(origin)) {
      await writeSecurityLog({
        env,
        type: "client_security_event",
        level: "warning",
        message: "Blocked telemetry request from forbidden origin",
        route: ROUTE,
        metadata: {
          blockedReason: "forbidden_origin",
          origin
        }
      });

      return jsonResponse(
        buildBlockedResponse("Forbidden origin.", { action: "block" }),
        403
      );
    }

    const security = await runRouteSecurity({
      req: request,
      route: ROUTE,
      allowedOrigins: ALLOWED_ORIGINS,
      body,
      sessionId: safeString(body.sessionId || "", 120),
      behavior: {
        userAgent: safeString(body.userAgent || "", 500),
        route: ROUTE
      },
      abuseSuccess: true
    });

    ip = security.ip || "unknown";

    if (security.rateLimitResult && !security.rateLimitResult.allowed) {
      await writeSecurityLog({
        env,
        type: "client_security_event",
        level: "warning",
        message: "Security log endpoint rate limited",
        ip,
        route: ROUTE,
        metadata: {
          action: security.rateLimitResult.recommendedAction || "throttle"
        }
      });

      return jsonResponse(
        {
          success: false,
          message: "Too many requests."
        },
        429
      );
    }

    if (security.finalAction === "block") {
      await writeSecurityLog({
        env,
        type: "client_security_event",
        level: "warning",
        message: "Suspicious telemetry request blocked",
        ip,
        route: ROUTE,
        metadata: {
          finalAction: security.finalAction,
          containmentAction: security.containmentAction,
          combinedRisk: safeNumber(security.combinedRisk, 0)
        }
      });

      return jsonResponse(
        buildBlockedResponse("Suspicious request blocked.", {
          action: "block"
        }),
        403
      );
    }

    if (security.finalAction === "challenge") {
      await writeSecurityLog({
        env,
        type: "client_security_event",
        level: "warning",
        message: "Telemetry request requires verification",
        ip,
        route: ROUTE,
        metadata: {
          finalAction: security.finalAction,
          containmentAction: security.containmentAction,
          combinedRisk: safeNumber(security.combinedRisk, 0)
        }
      });

      return jsonResponse(
        buildBlockedResponse("Verification required.", {
          action: "challenge"
        }),
        403
      );
    }

    const type = safeString(body.type, 50);
    const message = safeString(body.message, 500);

    const freshRequestResult = await validateFreshRequest({
      env,
      requestAt: body.eventAt,
      nonce: safeString(body.nonce, 200),
      scope: buildTelemetryNonceScope(type),
      requireNonce: Boolean(body.nonce),
      requireNonceStorage: true,
      maxAgeMs: MAX_EVENT_AGE_MS,
      futureToleranceMs: EVENT_FUTURE_TOLERANCE_MS,
      nonceTtlMs: 10 * 60 * 1000
    });

    if (!freshRequestResult.ok) {
      await writeSecurityLog({
        env,
        type: "client_security_event",
        level: "warning",
        message: "Rejected replayed or stale telemetry request",
        ip,
        route: ROUTE,
        metadata: {
          freshnessCode: safeString(freshRequestResult.code, 100)
        }
      });

      return jsonResponse(
        {
          success: false,
          message: "Invalid telemetry request."
        },
        400
      );
    }

    await writeSecurityLog({
      env,
      type: type || "client_security_event",
      level: "info",
      message: message || "Client telemetry received",
      ip,
      route: ROUTE,
      metadata: sanitizeMetadata({
        source: "client_untrusted",
        eventAt: safeNumber(body.eventAt, 0),
        receivedAt: Date.now(),
        ageMs: safeNumber(freshRequestResult.ageMs, 0),
        sessionId: safeString(body.sessionId || "", 120)
      })
    });

    return jsonResponse({
      success: true,
      action:
        security.finalAction === "allow"
          ? "allow"
          : security.finalAction
    });
  } catch (error) {
    console.error("Security log API error:", error);

    try {
      await writeSecurityLog({
        env,
        type: "client_security_event",
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
      {
        success: false,
        message: "Internal server error."
      },
      500
    );
  }
}
