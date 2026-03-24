import { getContainmentState } from "./_security-containment.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import {
  safeString,
  buildMethodNotAllowedResponse,
  buildBlockedResponse
} from "./_api-security.js";

const ROUTE = "/api/public-security-state";
const PRIMARY_DOMAIN = "aethra-c46.pages.dev";

/* ---------------- RESPONSE ---------------- */

function normalizeOrigin(origin = "") {
  const raw = safeString(origin || "", 200).trim();

  if (!raw) return "";

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

function normalizeHostname(hostname = "") {
  return safeString(hostname || "", 200).trim().toLowerCase();
}

function normalizeIp(value = "") {
  return (
    safeString(value || "unknown", 100)
      .replace(/[^a-fA-F0-9:.,]/g, "")
      .slice(0, 100) || "unknown"
  );
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

function getRequestHost(request) {
  return normalizeHostname((request.headers.get("host") || "").split(":")[0]);
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

function buildHeaders(origin = "") {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    "pragma": "no-cache",
    "expires": "0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer"
  };

  if (origin && isOriginAllowed(origin)) {
    headers["access-control-allow-origin"] = normalizeOrigin(origin);
    headers["access-control-allow-methods"] = "GET, OPTIONS";
    headers["access-control-allow-headers"] = "Content-Type";
    headers["vary"] = "Origin";
  }

  return headers;
}

function jsonResponse(origin, payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: buildHeaders(origin)
  });
}

function safeTimestamp(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) && num >= 0 ? Math.floor(num) : fallback;
}

function buildPublicFlags(flags = {}) {
  return {
    freezeRegistrations: flags?.freezeRegistrations === true,
    disableProfileEdits: flags?.disableProfileEdits === true,
    readOnlyMode: flags?.readOnlyMode === true,
    disableUploads: flags?.disableUploads === true,
    forceCaptcha: flags?.forceCaptcha === true
  };
}

async function logPublicState({
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

/* ---------------- HANDLERS ---------------- */

export async function onRequestGet(context) {
  const { request, env } = context;
  const origin = request.headers.get("origin") || "";
  const host = getRequestHost(request);

  const actor = createActorContext({
    req: request,
    body: {},
    route: ROUTE
  });

  try {
    if (origin && !isOriginAllowed(origin)) {
      await logPublicState({
        env,
        type: "public_security_state_forbidden_origin",
        level: "warning",
        request,
        actor,
        message: "Forbidden origin for public security state endpoint.",
        metadata: {
          origin: normalizeOrigin(origin)
        }
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Forbidden origin.", { action: "block" }),
        403
      );
    }

    if (!isExpectedHostname(host)) {
      await logPublicState({
        env,
        type: "public_security_state_forbidden_host",
        level: "warning",
        request,
        actor,
        message: "Forbidden host for public security state endpoint.",
        metadata: {
          host
        }
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Forbidden host.", { action: "block" }),
        403
      );
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
        key: `public-security-state:${actor.actorKey}`,
        limit: 60,
        windowMs: 60 * 1000
      },
      abuseSuccess: true,
      containmentConfig: {
        isWriteAction: false,
        actionType: "public_security_state_read",
        routeSensitivity: "medium"
      }
    });

    const finalAction = safeString(
      security?.risk?.finalAction || "allow",
      50
    ).toLowerCase();

    if (finalAction === "block") {
      await logPublicState({
        env,
        type: "public_security_state_blocked",
        level: "warning",
        request,
        actor,
        message: "Public security state request blocked by orchestrator.",
        metadata: {
          riskScore: security?.risk?.riskScore || 0
        }
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Request blocked.", { action: "block" }),
        403
      );
    }

    if (finalAction === "challenge") {
      await logPublicState({
        env,
        type: "public_security_state_challenged",
        level: "warning",
        request,
        actor,
        message: "Public security state request challenged by orchestrator.",
        metadata: {
          riskScore: security?.risk?.riskScore || 0
        }
      });

      return jsonResponse(
        origin,
        {
          success: false,
          action: "challenge",
          message: "Additional verification required."
        },
        429
      );
    }

    const state = await getContainmentState(env);
    const flags = buildPublicFlags(state?.flags || {});
    const mode = flags.readOnlyMode ? "restricted" : "normal";

    const payload = {
      success: true,
      action: "allow",
      mode,
      updatedAt: safeTimestamp(state?.updatedAt, 0),
      expiresAt: safeTimestamp(state?.expiresAt, 0),
      flags
    };

    return jsonResponse(origin, payload, 200);
  } catch (error) {
    try {
      await logPublicState({
        env,
        type: "public_security_state_error",
        level: "error",
        request,
        actor,
        message: "Failed to fetch public security state.",
        metadata: {
          error: error instanceof Error ? error.message : "unknown_error"
        }
      });
    } catch {}

    return jsonResponse(
      origin,
      {
        success: false,
        action: "deny",
        message: "Internal server error."
      },
      500
    );
  }
}

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("origin") || "";

  return new Response(null, {
    status: 204,
    headers: buildHeaders(origin)
  });
}

export async function onRequest(context) {
  const method = context.request.method;
  const origin = context.request.headers.get("origin") || "";

  if (method === "GET") {
    return onRequestGet(context);
  }

  if (method === "OPTIONS") {
    return onRequestOptions(context);
  }

  return jsonResponse(origin, buildMethodNotAllowedResponse(), 405);
}
