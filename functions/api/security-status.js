import { buildSecurityStatus } from "./_security-status.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  buildMethodNotAllowedResponse
} from "./_api-security.js";
import { getAdaptiveThreatMode } from "./_adaptive-threat-mode.js";
import { getContainmentState } from "./_security-containment.js";

const ROUTE = "/api/security-status";

/* -------------------- RESPONSE -------------------- */

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

/* -------------------- UTIL -------------------- */

function normalizeIp(value = "") {
  return safeString(value || "unknown", 100)
    .replace(/[^a-fA-F0-9:.,]/g, "")
    .slice(0, 100) || "unknown";
}

function getClientIp(request) {
  const cfIp = request.headers.get("cf-connecting-ip");
  if (cfIp) {
    return normalizeIp(cfIp.trim());
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

function unauthorizedResponse() {
  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

/* -------------------- HANDLER -------------------- */

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    return jsonResponse(buildMethodNotAllowedResponse(), 405);
  }

  const clientIp = getClientIp(request);

  try {
    const adminKey = safeString(
      request.headers.get("x-security-admin-key"),
      200
    );

    if (!env.SECURITY_ADMIN_API_KEY || adminKey !== env.SECURITY_ADMIN_API_KEY) {
      writeSecurityLog({
        env,
        type: "security_status_unauthorized",
        level: "warning",
        route: ROUTE,
        ip: clientIp,
        message: "Unauthorized attempt to access security status endpoint.",
        metadata: { method: request.method }
      }).catch(() => {});

      return unauthorizedResponse();
    }

    const [adaptiveState, containmentState] = await Promise.all([
      getAdaptiveThreatMode(env),
      getContainmentState(env)
    ]);

    const payload = buildSecurityStatus({
      adaptiveState,
      threatSnapshot: {},
      containment: containmentState,
      timestamp: Date.now()
    });

    writeSecurityLog({
      env,
      type: "security_status_accessed",
      level: "info",
      route: ROUTE,
      ip: clientIp,
      message: "Security status endpoint accessed successfully.",
      metadata: {
        mode: payload.mode,
        systemHealth: payload.systemHealth
      }
    }).catch(() => {});

    return jsonResponse(payload, 200);
  } catch (error) {
    writeSecurityLog({
      env,
      type: "security_status_error",
      level: "error",
      route: ROUTE,
      ip: clientIp,
      message: "Failed to build security status response.",
      metadata: {
        error: error instanceof Error ? error.message : "unknown_error"
      }
    }).catch(() => {});

    return jsonResponse({ ok: false, error: "internal_error" }, 500);
  }
}
