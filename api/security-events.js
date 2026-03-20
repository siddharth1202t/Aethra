import {
  getRecentSecurityEvents
} from "../_security-events-store.js";
import { writeSecurityLog } from "../_security-log-writer.js";
import { safeString, buildMethodNotAllowedResponse } from "../_api-security.js";
import { getAdaptiveThreatMode } from "../_adaptive-threat-mode.js";
import { getContainmentState } from "../_security-containment.js";

const ROUTE = "/api/security-events";

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

function parseLimit(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return 50;
  return Math.min(100, Math.max(1, Math.floor(num)));
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
        type: "security_events_unauthorized",
        level: "warning",
        route: ROUTE,
        ip: clientIp,
        message: "Unauthorized attempt to access security events endpoint.",
        metadata: {
          method: req.method
        }
      });

      return res.status(404).json(buildUnauthorizedResponse());
    }

    const limit = parseLimit(req.query?.limit);
    const severity = safeString(req.query?.severity || "", 20).toLowerCase();
    const action = safeString(req.query?.action || "", 20).toLowerCase();
    const type = safeString(req.query?.type || "", 80).toLowerCase();

    const [events, adaptiveState, containmentState] = await Promise.all([
      getRecentSecurityEvents({
        limit,
        severity,
        action,
        type
      }),
      getAdaptiveThreatMode(),
      getContainmentState()
    ]);

    await writeSecurityLog({
      type: "security_events_accessed",
      level: "info",
      route: ROUTE,
      ip: clientIp,
      message: "Security events endpoint accessed successfully.",
      metadata: {
        returnedEvents: events.length
      }
    });

    return res.status(200).json({
      ok: true,
      timestamp: new Date().toISOString(),
      count: events.length,
      filters: {
        limit,
        severity: severity || "",
        action: action || "",
        type: type || ""
      },
      mode: adaptiveState?.mode || "normal",
      containmentMode: containmentState?.mode || "normal",
      events
    });
  } catch (error) {
    await writeSecurityLog({
      type: "security_events_error",
      level: "error",
      route: ROUTE,
      ip: clientIp,
      message: "Failed to fetch security events.",
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
