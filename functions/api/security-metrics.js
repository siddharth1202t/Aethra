import { buildSecurityMetrics } from "./_security-metrics.js";
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

const ROUTE = "/api/security-metrics";
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 100;

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
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
  if (typeof cfIp === "string" && cfIp.trim()) {
    return normalizeIp(cfIp.trim());
  }

  const forwarded = request.headers.get("x-forwarded-for");
  if (typeof forwarded === "string" && forwarded.trim()) {
    return normalizeIp(forwarded.split(",")[0].trim());
  }

  const realIp = request.headers.get("x-real-ip");
  if (typeof realIp === "string" && realIp.trim()) {
    return normalizeIp(realIp.trim());
  }

  return "unknown";
}

function parseLimit(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return DEFAULT_LIMIT;
  return Math.min(MAX_LIMIT, Math.max(1, Math.floor(num)));
}

function buildUnauthorizedResponse() {
  return {
    ok: false,
    error: "not_found"
  };
}

async function recordUnauthorizedAccess({ env, ip, method }) {
  try {
    await appendSecurityEvent(env, {
      type: "admin_endpoint_unauthorized",
      severity: "warning",
      action: "block",
      route: ROUTE,
      ip,
      reason: "invalid_admin_key",
      message:
        "Unauthorized attempt to access protected security metrics endpoint.",
      metadata: {
        method
      }
    });
  } catch (error) {
    console.error("Security metrics unauthorized event write failed:", error);
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    return jsonResponse(buildMethodNotAllowedResponse(), 405);
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
        type: "security_metrics_unauthorized",
        level: "warning",
        route: ROUTE,
        ip: clientIp,
        message: "Unauthorized attempt to access security metrics endpoint.",
        metadata: {
          method: request.method
        }
      });

      await recordUnauthorizedAccess({
        env,
        ip: clientIp,
        method: request.method
      });

      return jsonResponse(buildUnauthorizedResponse(), 404);
    }

    const url = new URL(request.url);
    const limit = parseLimit(url.searchParams.get("limit"));

    const [adaptiveState, containmentState, events] = await Promise.all([
      getAdaptiveThreatMode(env),
      getContainmentState(env),
      getRecentSecurityEvents(env, { limit })
    ]);

    const payload = buildSecurityMetrics({
      adaptiveState,
      containmentState,
      events,
      timestamp: Date.now()
    });

    await writeSecurityLog({
      env,
      type: "security_metrics_accessed",
      level: "info",
      route: ROUTE,
      ip: clientIp,
      message: "Security metrics endpoint accessed successfully.",
      metadata: {
        limit,
        mode: payload.mode,
        threatPressure: payload.threatPressure
      }
    });

    return jsonResponse(payload, 200);
  } catch (error) {
    try {
      await writeSecurityLog({
        env,
        type: "security_metrics_error",
        level: "error",
        route: ROUTE,
        ip: clientIp,
        message: "Failed to fetch security metrics.",
        metadata: {
          error: error instanceof Error ? error.message : "unknown_error"
        }
      });
    } catch {}

    return jsonResponse(
      {
        ok: false,
        error: "internal_error"
      },
      500
    );
  }
}
