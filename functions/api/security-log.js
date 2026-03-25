import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import {
  safeString,
  sanitizeBody,
  buildMethodNotAllowedResponse,
  buildBlockedResponse,
  buildChallengeResponse,
  buildDeniedResponse,
  runRouteSecurity
} from "./_api-security.js";
import { validateFreshRequest } from "./_request-freshness.js";

const ROUTE = "/api/security-log";
const MAX_BODY_KEYS = 20;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;
const MAX_MESSAGE_LENGTH = 500;
const MAX_SOURCE_LENGTH = 100;
const MAX_EVENT_NAME_LENGTH = 100;
const MAX_METADATA_ENTRIES = 12;
const MAX_METADATA_VALUE_LENGTH = 300;

const ALLOWED_CLIENT_EVENTS = new Set([
  "client_error",
  "auth_ui_error",
  "turnstile_ui_error",
  "frontend_security_signal",
  "session_client_warning",
  "suspicious_client_state"
]);

const ALLOWED_CLIENT_SEVERITIES = new Set([
  "info",
  "warning",
  "error"
]);

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "pragma": "no-cache",
      "x-content-type-options": "nosniff"
    }
  });
}

function normalizeIp(value = "") {
  return (
    safeString(value || "unknown", 100)
      .replace(/[^a-fA-F0-9:.,]/g, "")
      .slice(0, 100) || "unknown"
  );
}

function getClientIp(request) {
  return normalizeIp(
    request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-forwarded-for")?.split(",")[0] ||
      request.headers.get("x-real-ip") ||
      "unknown"
  );
}

function normalizeSeverity(value = "") {
  const normalized = safeString(value || "warning", 20).toLowerCase();
  return ALLOWED_CLIENT_SEVERITIES.has(normalized) ? normalized : "warning";
}

function normalizeClientEventType(value = "") {
  const normalized = safeString(value || "", MAX_EVENT_NAME_LENGTH).toLowerCase();
  return ALLOWED_CLIENT_EVENTS.has(normalized)
    ? normalized
    : "frontend_security_signal";
}

function sanitizeMetadata(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {};
  }

  const entries = Object.entries(input).slice(0, MAX_METADATA_ENTRIES);
  const output = {};

  for (const [rawKey, rawValue] of entries) {
    const key = safeString(rawKey || "", 80).trim();
    if (!key) continue;

    if (
      rawValue === null ||
      typeof rawValue === "number" ||
      typeof rawValue === "boolean"
    ) {
      output[key] = rawValue;
      continue;
    }

    if (typeof rawValue === "string") {
      output[key] = safeString(rawValue, MAX_METADATA_VALUE_LENGTH);
      continue;
    }

    if (Array.isArray(rawValue)) {
      output[key] = rawValue
        .slice(0, 10)
        .map((item) => safeString(String(item), 80));
      continue;
    }

    if (typeof rawValue === "object") {
      output[key] = safeString(JSON.stringify(rawValue), MAX_METADATA_VALUE_LENGTH);
    }
  }

  return output;
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
      method: request.method,
      ...metadata
    }
  });
}

function buildSafeClientLogPayload(body, actor, request, degraded = false) {
  const clientEvent = normalizeClientEventType(body.event || body.type || "");
  const severity = normalizeSeverity(body.level || body.severity || "warning");
  const message = safeString(
    body.message || body.reason || "Client security telemetry received",
    MAX_MESSAGE_LENGTH
  );
  const source = safeString(body.source || "frontend", MAX_SOURCE_LENGTH);
  const metadata = sanitizeMetadata(body.metadata);

  return {
    type: "client_security_telemetry",
    level: severity,
    message,
    ip: actor?.ip || getClientIp(request),
    route: ROUTE,
    userId: actor?.userId || null,
    sessionId: actor?.sessionId || null,
    metadata: {
      actorKey: actor?.actorKey || null,
      routeKey: actor?.routeKey || null,
      clientEvent,
      source,
      degraded: degraded === true,
      originalRoute: safeString(body.route || "", 200),
      userAgent: safeString(request.headers.get("user-agent") || "", 300),
      ...metadata
    }
  };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return jsonResponse(buildMethodNotAllowedResponse(), 405);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return jsonResponse(
      buildDeniedResponse("Unsupported content type", {
        action: "deny"
      }),
      415
    );
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return jsonResponse(
      buildDeniedResponse("Request body too large", {
        action: "deny"
      }),
      413
    );
  }

  try {
    let rawBody = {};

    try {
      rawBody = await request.json();
    } catch {
      return jsonResponse(
        buildDeniedResponse("Invalid JSON body", {
          action: "deny"
        }),
        400
      );
    }

    const body = sanitizeBody(rawBody, MAX_BODY_KEYS);

    const actor = createActorContext({
      req: request,
      body,
      route: ROUTE
    });

    const security = await runRouteSecurity({
      env,
      req: request,
      route: ROUTE,
      body,
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
      security?.risk?.finalAction || "allow",
      50
    ).toLowerCase();

    const degraded = security?.risk?.degraded === true;

    if (finalAction === "block") {
      await logRouteEvent({
        env,
        type: "security_log_blocked",
        level: "warning",
        message: "Security log submission blocked by route security",
        actor,
        request,
        metadata: {
          riskScore: security?.risk?.riskScore || 0,
          degraded
        }
      });

      return jsonResponse(
        buildBlockedResponse("Request blocked", {
          action: "block",
          degraded
        }),
        403
      );
    }

    if (finalAction === "challenge") {
      await logRouteEvent({
        env,
        type: "security_log_challenged",
        level: "warning",
        message: "Security log submission challenged by route security",
        actor,
        request,
        metadata: {
          riskScore: security?.risk?.riskScore || 0,
          degraded
        }
      });

      return jsonResponse(
        buildChallengeResponse("Additional verification required", {
          action: "challenge",
          degraded
        }),
        403
      );
    }

    const freshness = await validateFreshRequest({
      env,
      requestAt: body.eventAt || body.requestAt || body.timestamp,
      nonce: safeString(body.nonce || "", 200),
      scope: "security-log",
      requireNonce: Boolean(body.nonce),
      requireNonceStorage: true,
      maxAgeMs: 2 * 60 * 1000,
      futureToleranceMs: 15 * 1000,
      nonceTtlMs: 10 * 60 * 1000
    });

    if (!freshness.ok) {
      await logRouteEvent({
        env,
        type: "security_log_rejected_freshness",
        level: "warning",
        message: "Security log submission rejected due to freshness validation failure",
        actor,
        request,
        metadata: {
          code: safeString(freshness.code || "invalid_freshness", 100),
          degraded: freshness.degraded === true
        }
      });

      return jsonResponse(
        buildDeniedResponse("Invalid telemetry request", {
          action: "deny",
          degraded: freshness.degraded === true
        }),
        400
      );
    }

    const safePayload = buildSafeClientLogPayload(
      body,
      actor,
      request,
      degraded || freshness.degraded === true
    );

    const ok = await writeSecurityLog({
      env,
      ...safePayload
    });

    return jsonResponse({
      success: true,
      action: "allow",
      degraded: degraded || freshness.degraded === true,
      logged: ok === true
    });
  } catch (error) {
    console.error("security-log route error:", error);

    try {
      await writeSecurityLog({
        env,
        type: "security_log_route_error",
        level: "error",
        message: "Unhandled error in security-log route",
        route: ROUTE,
        metadata: {
          error: safeString(error?.message || "unknown_error", 300)
        }
      });
    } catch {}

    return jsonResponse(
      buildDeniedResponse("Internal server error", {
        action: "deny"
      }),
      500
    );
  }
}
