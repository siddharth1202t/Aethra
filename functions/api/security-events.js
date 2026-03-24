import {
  getRecentSecurityEvents,
  appendSecurityEvent
} from "./_security-event-store.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  buildMethodNotAllowedResponse,
  buildBlockedResponse
} from "./_api-security.js";
import { getAdaptiveThreatMode } from "./_adaptive-threat-mode.js";
import { getContainmentState } from "./_security-containment.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import { createActorContext } from "./_actor-context.js";

const ROUTE = "/api/security-events";
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const MAX_ADMIN_KEY_LENGTH = 300;
const PRIMARY_DOMAIN = "aethra-c46.pages.dev";

const ALLOWED_SEVERITIES = new Set(["", "info", "warning", "error", "critical"]);
const ALLOWED_ACTIONS = new Set([
  "",
  "allow",
  "observe",
  "throttle",
  "challenge",
  "block",
  "lock",
  "contain"
]);

/* ---------------- RESPONSE ---------------- */

function buildHeaders(origin = "") {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "pragma": "no-cache",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer"
  };

  if (origin && isOriginAllowed(origin)) {
    headers["access-control-allow-origin"] = normalizeOrigin(origin);
    headers["vary"] = "origin";
  }

  return headers;
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: buildHeaders(origin)
  });
}

/* ---------------- NORMALIZATION ---------------- */

function normalizeIp(ip = "") {
  return (
    safeString(ip || "unknown", 100)
      .replace(/[^a-fA-F0-9:.,]/g, "")
      .slice(0, 100) || "unknown"
  );
}

function normalizeOrigin(origin = "") {
  try {
    return new URL(origin).origin.toLowerCase();
  } catch {
    return "";
  }
}

function normalizeHostname(hostname = "") {
  return safeString(hostname || "", 200).trim().toLowerCase();
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

function buildUnauthorizedResponse() {
  return {
    ok: false,
    error: "not_found"
  };
}

function parseLimit(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return DEFAULT_LIMIT;
  return Math.min(MAX_LIMIT, Math.max(1, Math.floor(num)));
}

function normalizeSeverityFilter(value = "") {
  const normalized = safeString(value || "", 20).toLowerCase();
  return ALLOWED_SEVERITIES.has(normalized) ? normalized : "";
}

function normalizeActionFilter(value = "") {
  const normalized = safeString(value || "", 20).toLowerCase();
  return ALLOWED_ACTIONS.has(normalized) ? normalized : "";
}

function normalizeTypeFilter(value = "") {
  return safeString(value || "", 80).trim().toLowerCase();
}

function timingSafeEqual(a, b) {
  const aStr = safeString(a || "", MAX_ADMIN_KEY_LENGTH);
  const bStr = safeString(b || "", MAX_ADMIN_KEY_LENGTH);

  if (!aStr || !bStr) return false;
  if (aStr.length !== bStr.length) return false;

  let diff = 0;
  for (let i = 0; i < aStr.length; i += 1) {
    diff |= aStr.charCodeAt(i) ^ bStr.charCodeAt(i);
  }

  return diff === 0;
}

/* ---------------- LOGGING ---------------- */

async function logSecurityEvents({
  env,
  type,
  level,
  request,
  actor,
  message,
  metadata = {}
}) {
  await writeSecurityLog({
    env,
    type,
    level,
    route: ROUTE,
    ip: actor?.ip || getClientIp(request),
    userId: actor?.userId || null,
    sessionId: actor?.sessionId || null,
    message,
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

async function recordUnauthorizedAccess({ env, request, actor }) {
  try {
    await appendSecurityEvent(env, {
      type: "admin_endpoint_unauthorized",
      severity: "warning",
      action: "block",
      route: ROUTE,
      ip: actor?.ip || getClientIp(request),
      reason: "invalid_admin_key",
      message: "Unauthorized attempt to access protected security events endpoint.",
      metadata: {
        method: request.method,
        actorKey: actor?.actorKey || null,
        routeKey: actor?.routeKey || null,
        host: getRequestHost(request),
        origin: normalizeOrigin(request.headers.get("origin") || "")
      }
    });
  } catch (error) {
    console.error("Security events unauthorized event write failed:", error);
  }
}

async function recordAuthorizedAccess({
  env,
  request,
  actor,
  eventCount,
  mode,
  containmentMode,
  filters
}) {
  try {
    await appendSecurityEvent(env, {
      type: "security_events_accessed",
      severity: "info",
      action: "observe",
      route: ROUTE,
      ip: actor?.ip || getClientIp(request),
      mode,
      reason: "admin_events_check",
      message: "Protected security events endpoint accessed successfully.",
      metadata: {
        actorKey: actor?.actorKey || null,
        routeKey: actor?.routeKey || null,
        returnedEvents: eventCount,
        containmentMode,
        filterSeverity: filters.severity || "",
        filterAction: filters.action || "",
        filterType: filters.type || "",
        limit: filters.limit
      }
    });
  } catch (error) {
    console.error("Security events access event write failed:", error);
  }
}

/* ---------------- MAIN HANDLER ---------------- */

export async function onRequest(context) {
  const { request, env } = context;
  const origin = request.headers.get("origin") || "";
  const host = getRequestHost(request);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        ...buildHeaders(origin),
        "access-control-allow-methods": "GET, OPTIONS",
        "access-control-allow-headers": "Content-Type, x-security-admin-key"
      }
    });
  }

  if (request.method !== "GET") {
    return json(buildMethodNotAllowedResponse(), 405, origin);
  }

  const actor = createActorContext({
    req: request,
    body: {},
    route: ROUTE
  });

  try {
    if (origin && !isOriginAllowed(origin)) {
      await logSecurityEvents({
        env,
        type: "security_events_forbidden_origin",
        level: "warning",
        request,
        actor,
        message: "Forbidden origin for security events endpoint.",
        metadata: {
          origin: normalizeOrigin(origin)
        }
      });

      return json(
        buildBlockedResponse("Forbidden origin.", { action: "block" }),
        403,
        origin
      );
    }

    if (!isExpectedHostname(host)) {
      await logSecurityEvents({
        env,
        type: "security_events_forbidden_host",
        level: "warning",
        request,
        actor,
        message: "Forbidden host for security events endpoint.",
        metadata: {
          host
        }
      });

      return json(
        buildBlockedResponse("Forbidden host.", { action: "block" }),
        403,
        origin
      );
    }

    const configuredAdminKey = safeString(
      env?.SECURITY_ADMIN_API_KEY || "",
      MAX_ADMIN_KEY_LENGTH
    );
    const providedAdminKey = safeString(
      request.headers.get("x-security-admin-key") || "",
      MAX_ADMIN_KEY_LENGTH
    );

    if (!configuredAdminKey) {
      await logSecurityEvents({
        env,
        type: "security_events_misconfigured",
        level: "critical",
        request,
        actor,
        message: "SECURITY_ADMIN_API_KEY is missing for security events endpoint."
      });

      return json(buildUnauthorizedResponse(), 404, origin);
    }

    const security = await runSecurityOrchestrator({
      env,
      req: request,
      body: {},
      route: ROUTE,
      context: {
        ip: actor.ip,
        sessionId: actor.sessionId,
        userId: actor.userId
      },
      rateLimitConfig: {
        key: `security-events:${actor.actorKey}`,
        limit: 20,
        windowMs: 60 * 1000
      },
      abuseSuccess: true,
      containmentConfig: {
        isWriteAction: false,
        actionType: "security_admin_read",
        routeSensitivity: "critical"
      }
    });

    const finalAction = safeString(
      security?.risk?.finalAction || "allow",
      50
    ).toLowerCase();

    if (finalAction === "block" || finalAction === "challenge") {
      await logSecurityEvents({
        env,
        type:
          finalAction === "block"
            ? "security_events_blocked"
            : "security_events_challenged",
        level: "warning",
        request,
        actor,
        message:
          finalAction === "block"
            ? "Security events endpoint blocked by orchestrator."
            : "Security events endpoint challenged by orchestrator.",
        metadata: {
          riskScore: security?.risk?.riskScore || 0,
          finalAction
        }
      });

      return json(buildUnauthorizedResponse(), 404, origin);
    }

    if (!timingSafeEqual(providedAdminKey, configuredAdminKey)) {
      await logSecurityEvents({
        env,
        type: "security_events_unauthorized",
        level: "warning",
        request,
        actor,
        message: "Unauthorized attempt to access security events endpoint."
      });

      await recordUnauthorizedAccess({
        env,
        request,
        actor
      });

      return json(buildUnauthorizedResponse(), 404, origin);
    }

    const url = new URL(request.url);

    const filters = {
      limit: parseLimit(url.searchParams.get("limit")),
      severity: normalizeSeverityFilter(url.searchParams.get("severity") || ""),
      action: normalizeActionFilter(url.searchParams.get("action") || ""),
      type: normalizeTypeFilter(url.searchParams.get("type") || "")
    };

    const [events, adaptiveState, containmentState] = await Promise.all([
      getRecentSecurityEvents(env, filters),
      getAdaptiveThreatMode(env),
      getContainmentState(env)
    ]);

    await logSecurityEvents({
      env,
      type: "security_events_accessed",
      level: "info",
      request,
      actor,
      message: "Security events endpoint accessed successfully.",
      metadata: {
        returnedEvents: Array.isArray(events) ? events.length : 0,
        filterSeverity: filters.severity || "",
        filterAction: filters.action || "",
        filterType: filters.type || "",
        limit: filters.limit
      }
    });

    await recordAuthorizedAccess({
      env,
      request,
      actor,
      eventCount: Array.isArray(events) ? events.length : 0,
      mode: adaptiveState?.mode || "normal",
      containmentMode: containmentState?.mode || "normal",
      filters
    });

    return json(
      {
        ok: true,
        timestamp: new Date().toISOString(),
        count: Array.isArray(events) ? events.length : 0,
        filters: {
          limit: filters.limit,
          severity: filters.severity || "",
          action: filters.action || "",
          type: filters.type || ""
        },
        mode: adaptiveState?.mode || "normal",
        containmentMode: containmentState?.mode || "normal",
        events: Array.isArray(events) ? events : []
      },
      200,
      origin
    );
  } catch (error) {
    try {
      await logSecurityEvents({
        env,
        type: "security_events_error",
        level: "error",
        request,
        actor,
        message: "Failed to fetch security events.",
        metadata: {
          error: error instanceof Error ? error.message : "unknown_error"
        }
      });
    } catch {}

    return json(
      {
        ok: false,
        error: "internal_error"
      },
      500,
      origin
    );
  }
}
