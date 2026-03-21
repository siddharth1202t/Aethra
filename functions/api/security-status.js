import { buildSecurityStatus } from "../_security-status.js";
import { writeSecurityLog } from "../_security-log-writer.js";
import { safeString, buildMethodNotAllowedResponse } from "../_api-security.js";
import { getAdaptiveThreatMode } from "../_adaptive-threat-mode.js";
import { getContainmentState } from "../_security-containment.js";

const ROUTE = "/api/security-status";

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim().slice(0, 100);
  }

  const realIp = req.headers["x-real-ip"];
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

export default async function handler(req, res) {
  if (req.method !== "GET") {
    const response = buildMethodNotAllowedResponse(["GET"]);
    return res.status(response.status).json(response.body);
  }

  const clientIp = getClientIp(req);

  try {
    const adminKey = safeString(
      req.headers["x-security-admin-key"] || "",
      200
    );

    if (
      !process.env.SECURITY_ADMIN_API_KEY ||
      adminKey !== process.env.SECURITY_ADMIN_API_KEY
    ) {
      await writeSecurityLog({
        type: "security_status_unauthorized",
        level: "warning",
        route: ROUTE,
        ip: clientIp,
        message: "Unauthorized attempt to access security status endpoint.",
        metadata: {
          method: req.method
        }
      });

      return res.status(404).json(buildUnauthorizedResponse());
    }

    // ✅ FIXED: correct async calls
    const adaptiveState = await getAdaptiveThreatMode();
    const containmentState = await getContainmentState();

    // (optional: future use)
    const threatSnapshot = {};

    // ✅ FIXED: correct payload structure
    const payload = buildSecurityStatus({
      adaptiveState,
      threatSnapshot,
      containment: containmentState,
      timestamp: Date.now()
    });

    await writeSecurityLog({
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

    return res.status(200).json(payload);
  } catch (error) {
    await writeSecurityLog({
      type: "security_status_error",
      level: "error",
      route: ROUTE,
      ip: clientIp,
      message: "Failed to build security status response.",
      metadata: {
        error: error instanceof Error ? error.message : "unknown_error"
      }
    });

    return res.status(500).json({
      ok: false,
      error: "internal_error"
    });
  }
}
