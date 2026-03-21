import { buildSecurityMetrics } from "./_security-metrics.js";
import { getRecentSecurityEvents, appendSecurityEvent } from "./_security-event-store.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import { safeString, buildMethodNotAllowedResponse } from "./_api-security.js";
import { getAdaptiveThreatMode } from "./_adaptive-threat-mode.js";
import { getContainmentState } from "./_security-containment.js";

const ROUTE = "/api/security-metrics";
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 100;

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

async function recordUnauthorizedAccess({ ip, method }) {
  try {
    await appendSecurityEvent({
      type: "admin_endpoint_unauthorized",
      severity: "warning",
      action: "block",
      route: ROUTE,
      ip,
      reason: "invalid_admin_key",
      message: "Unauthorized attempt to access protected security metrics endpoint.",
      metadata: {
        method
      }
    });
  } catch (error) {
    console.error("Security metrics unauthorized event write failed:", error);
  }
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
        type: "security_metrics_unauthorized",
        level: "warning",
        route: ROUTE,
        ip: clientIp,
        message: "Unauthorized attempt to access security metrics endpoint.",
        metadata: {
          method: req.method
        }
      });

      await recordUnauthorizedAccess({
        ip: clientIp,
        method: req.method
      });

      return res.status(404).json(buildUnauthorizedResponse());
    }

    const limit = parseLimit(req.query?.limit);

    const [adaptiveState, containmentState, events] = await Promise.all([
      getAdaptiveThreatMode(),
      getContainmentState(),
      getRecentSecurityEvents({ limit })
    ]);

    const payload = buildSecurityMetrics({
      adaptiveState,
      containmentState,
      events,
      timestamp: Date.now()
    });

    await writeSecurityLog({
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

    return res.status(200).json(payload);
  } catch (error) {
    await writeSecurityLog({
      type: "security_metrics_error",
      level: "error",
      route: ROUTE,
      ip: clientIp,
      message: "Failed to fetch security metrics.",
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
