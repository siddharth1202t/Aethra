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

function getClientIp(request) {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0].trim().slice(0, 100);
  }

  const realIp = request.headers.get("x-real-ip");
  if (realIp) {
    return realIp.trim().slice(0, 100);
  }

  return "unknown";
}

function unauthorizedResponse() {
  return jsonResponse({ ok: false, error: "not_found" }, 404);
}

/* -------------------- HANDLER -------------------- */

export async function onRequest(context) {
  const { request, env } = context;

  /* ---- METHOD CHECK ---- */
  if (request.method !== "GET") {
    const response = buildMethodNotAllowedResponse(["GET"]);
    return jsonResponse(response.body, response.status);
  }

  const clientIp = getClientIp(request);

  try {
    /* ---- ADMIN KEY VALIDATION ---- */
    const adminKey = safeString(
      request.headers.get("x-security-admin-key"),
      200
    );

    if (!env.SECURITY_ADMIN_API_KEY || adminKey !== env.SECURITY_ADMIN_API_KEY) {
      // fire and forget (don’t block response on logging)
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

    /* ---- PARALLEL FETCH (FASTER) ---- */
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

    // fire and forget logging
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
    // fire and forget logging
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
