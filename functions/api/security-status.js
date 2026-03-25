import { buildSecurityStatus } from "./_security-status.js";
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

const ROUTE = "/api/security-status";
const MAX_ADMIN_KEY_LENGTH = 300;
const PRIMARY_DOMAIN = "aethra-c46.pages.dev";

/* -------------------- RESPONSE -------------------- */

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

function jsonResponse(payload, status = 200, origin = "") {
  return new Response(JSON.stringify(payload), {
    status,
    headers: buildHeaders(origin)
  });
}

/* -------------------- UTIL -------------------- */

function normalizeIp(value = "") {
  return (
    safeString(value || "unknown", 100)
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

function unauthorizedResponse(origin = "") {
  return jsonResponse({ ok: false, error: "not_found" }, 404, origin);
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

async function logSecurityStatus({
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

/* -------------------- HANDLER -------------------- */

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
    return jsonResponse(buildMethodNotAllowedResponse(), 405, origin);
  }

  const actor = createActorContext({
    req: request,
    body: {},
    route: ROUTE
  });

  try {
    if (origin && !isOriginAllowed(origin)) {
      await logSecurityStatus({
        env,
        type: "security_status_forbidden_origin",
        level: "warning",
        request,
        actor,
        message: "Forbidden origin for security status endpoint.",
        metadata: {
          origin: normalizeOrigin(origin)
        }
      });

      return jsonResponse(
        buildBlockedResponse("Forbidden origin.", { action: "block" }),
        403,
        origin
      );
    }

    if (!isExpectedHostname(host)) {
      await logSecurityStatus({
        env,
        type: "security_status_forbidden_host",
        level: "warning",
        request,
        actor,
        message: "Forbidden host for security status endpoint.",
        metadata: {
          host
        }
      });

      return jsonResponse(
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
      request.headers.get("x-security-admin-key"),
      MAX_ADMIN_KEY_LENGTH
    );

    if (!configuredAdminKey) {
      await logSecurityStatus({
        env,
        type: "security_status_misconfigured",
        level: "critical",
        request,
        actor,
        message: "SECURITY_ADMIN_API_KEY is missing for security status endpoint."
      });

      return unauthorizedResponse(origin);
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
        key: `security-status:${actor.actorKey}`,
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

    if (finalAction === "block") {
      await logSecurityStatus({
        env,
        type: "security_status_blocked",
        level: "warning",
        request,
        actor,
        message: "Security status endpoint blocked by orchestrator.",
        metadata: {
          riskScore: security?.risk?.riskScore || 0,
          finalAction,
          degraded: security?.risk?.degraded === true
        }
      });

      return unauthorizedResponse(origin);
    }

    if (finalAction === "challenge") {
      await logSecurityStatus({
        env,
        type: "security_status_challenged",
        level: "warning",
        request,
        actor,
        message: "Security status endpoint challenged by orchestrator.",
        metadata: {
          riskScore: security?.risk?.riskScore || 0,
          finalAction,
          degraded: security?.risk?.degraded === true
        }
      });

      return unauthorizedResponse(origin);
    }

    if (!timingSafeEqual(providedAdminKey, configuredAdminKey)) {
      await logSecurityStatus({
        env,
        type: "security_status_unauthorized",
        level: "warning",
        request,
        actor,
        message: "Unauthorized attempt to access security status endpoint."
      });

      return unauthorizedResponse(origin);
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

    await logSecurityStatus({
      env,
      type: "security_status_accessed",
      level: "info",
      request,
      actor,
      message: "Security status endpoint accessed successfully.",
      metadata: {
        mode: payload?.mode || null,
        systemHealth: payload?.systemHealth || null,
        degraded: payload?.degraded === true
      }
    });

    return jsonResponse(payload, 200, origin);
  } catch (error) {
    await logSecurityStatus({
      env,
      type: "security_status_error",
      level: "error",
      request,
      actor,
      message: "Failed to build security status response.",
      metadata: {
        error: error instanceof Error ? error.message : "unknown_error"
      }
    });

    return jsonResponse({ ok: false, error: "internal_error" }, 500, origin);
  }
}
