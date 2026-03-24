import {
  getRecentSecurityEvents,
  appendSecurityEvent
} from "./_security-event-store.js";

import { writeSecurityLog } from "./_security-log-writer.js";

import {
  safeString,
  buildMethodNotAllowedResponse
} from "./_api-security.js";

import { getAdaptiveThreatMode } from "./_adaptive-threat-mode.js";
import { getContainmentState } from "./_security-containment.js";

const ROUTE = "/api/security-events";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

/* ---------------- helpers ---------------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function normalizeIp(ip = "") {
  return safeString(ip || "unknown", 100)
    .replace(/[^a-fA-F0-9:.,]/g, "")
    .slice(0, 100) || "unknown";
}

function getClientIp(request) {
  const cfIp = request.headers.get("cf-connecting-ip");
  if (cfIp) {
    return normalizeIp(cfIp);
  }

  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    return normalizeIp(forwarded.split(",")[0].trim());
  }

  const realIp = request.headers.get("x-real-ip");
  if (realIp) {
    return normalizeIp(realIp.trim());
  }

  return "unknown";
}

function buildUnauthorizedResponse() {
  return {
    ok: false,
    error: "not_found"
  };
}

function parseLimit(value) {
  const num = Number(value);

  if (!Number.isFinite(num)) {
    return DEFAULT_LIMIT;
  }

  return Math.min(MAX_LIMIT, Math.max(1, Math.floor(num)));
}

/* ---------------- event logs ---------------- */

async function recordUnauthorizedAccess({ env, ip, method }) {
  try {
    await appendSecurityEvent(env, {
      type: "admin_endpoint_unauthorized",
      severity: "warning",
      action: "block",
      route: ROUTE,
      ip,
      reason: "invalid_admin_key",
      message: "Unauthorized attempt to access protected security events endpoint.",
      metadata: {
        method
      }
    });
  } catch (error) {
    console.error("Security events unauthorized event write failed:", error);
  }
}

async function recordAuthorizedAccess({
  env,
  ip,
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
      ip,
      mode,
      reason: "admin_events_check",
      message: "Protected security events endpoint accessed successfully.",
      metadata: {
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

/* ---------------- main handler ---------------- */

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    return json(buildMethodNotAllowedResponse(), 405);
  }

  const clientIp = getClientIp(request);

  try {
    const adminKey = safeString(
      request.headers.get("x-security-admin-key") || "",
      200
    );

    if (
      !env.SECURITY_ADMIN_API_KEY ||
      adminKey !== env.SECURITY_ADMIN_API_KEY
    ) {
      await writeSecurityLog({
        env,
        type: "security_events_unauthorized",
        level: "warning",
        route: ROUTE,
        ip: clientIp,
        message: "Unauthorized attempt to access security events endpoint.",
        metadata: {
          method: request.method
        }
      });

      await recordUnauthorizedAccess({
        env,
        ip: clientIp,
        method: request.method
      });

      return json(buildUnauthorizedResponse(), 404);
    }

    const url = new URL(request.url);

    const filters = {
      limit: parseLimit(url.searchParams.get("limit")),
      severity: safeString(
        url.searchParams.get("severity") || "",
        20
      ).toLowerCase(),
      action: safeString(
        url.searchParams.get("action") || "",
        20
      ).toLowerCase(),
      type: safeString(
        url.searchParams.get("type") || "",
        80
      ).toLowerCase()
    };

    const [events, adaptiveState, containmentState] = await Promise.all([
      getRecentSecurityEvents(env, filters),
      getAdaptiveThreatMode(env),
      getContainmentState(env)
    ]);

    await writeSecurityLog({
      env,
      type: "security_events_accessed",
      level: "info",
      route: ROUTE,
      ip: clientIp,
      message: "Security events endpoint accessed successfully.",
      metadata: {
        returnedEvents: events.length,
        filterSeverity: filters.severity || "",
        filterAction: filters.action || "",
        filterType: filters.type || "",
        limit: filters.limit
      }
    });

    await recordAuthorizedAccess({
      env,
      ip: clientIp,
      eventCount: events.length,
      mode: adaptiveState?.mode || "normal",
      containmentMode: containmentState?.mode || "normal",
      filters
    });

    return json({
      ok: true,
      timestamp: new Date().toISOString(),
      count: events.length,
      filters: {
        limit: filters.limit,
        severity: filters.severity || "",
        action: filters.action || "",
        type: filters.type || ""
      },
      mode: adaptiveState?.mode || "normal",
      containmentMode: containmentState?.mode || "normal",
      events
    });
  } catch (error) {
    try {
      await writeSecurityLog({
        env,
        type: "security_events_error",
        level: "error",
        route: ROUTE,
        ip: clientIp,
        message: "Failed to fetch security events.",
        metadata: {
          error: error instanceof Error ? error.message : "unknown_error"
        }
      });
    } catch {}

    return json({
      ok: false,
      error: "internal_error"
    }, 500);
  }
}
