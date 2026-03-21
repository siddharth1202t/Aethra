import { buildSecurityStatus } from "../_security-status.js";
import { writeSecurityLog } from "../_security-log-writer.js";
import {
  safeString,
  buildMethodNotAllowedResponse
} from "../_api-security.js";
import { getAdaptiveThreatMode } from "../_adaptive-threat-mode.js";
import { getContainmentState } from "../_security-containment.js";

const ROUTE = "/api/security-status";

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function getClientIp(request) {
  const forwarded = request.headers.get("x-forwarded-for");
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim().slice(0, 100);
  }

  const realIp = request.headers.get("x-real-ip");
  if (typeof realIp === "string" && realIp.trim()) {
    return realIp.trim().slice(0, 100);
  }

  return "unknown";
}

function buildUnauthorizedResponse() {
  return {
    ok: false,
    error: "not_found"
  };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    const response = buildMethodNotAllowedResponse(["GET"]);
    return jsonResponse(response.body, response.status);
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
        type: "security_status_unauthorized",
        level: "warning",
        route: ROUTE,
        ip: clientIp,
        message: "Unauthorized attempt to access security status endpoint.",
        metadata: {
          method: request.method
        }
      });

      return jsonResponse(buildUnauthorizedResponse(), 404);
    }

    const adaptiveState = await getAdaptiveThreatMode(env);
    const containmentState = await getContainmentState(env);

    const threatSnapshot = {};

    const payload = buildSecurityStatus({
      adaptiveState,
      threatSnapshot,
      containment: containmentState,
      timestamp: Date.now()
    });

    await writeSecurityLog({
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
    });

    return jsonResponse(payload, 200);
  } catch (error) {
    await writeSecurityLog({
      env,
      type: "security_status_error",
      level: "error",
      route: ROUTE,
      ip: clientIp,
      message: "Failed to build security status response.",
      metadata: {
        error: error instanceof Error ? error.message : "unknown_error"
      }
    });

    return jsonResponse(
      {
        ok: false,
        error: "internal_error"
      },
      500
    );
  }
}
