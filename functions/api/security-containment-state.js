import { getContainmentState } from "./_security-containment.js";
import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import {
  buildMethodNotAllowedResponse,
  buildBlockedResponse,
  safeString
} from "./_api-security.js";

const ROUTE = "/api/security-containment-state";
const MAX_ADMIN_KEY_LENGTH = 300;
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
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer"
  };

  if (origin && isOriginAllowed(origin)) {
    headers["access-control-allow-origin"] = normalizeOrigin(origin);
    headers["access-control-allow-methods"] = "GET, OPTIONS";
    headers["access-control-allow-headers"] =
      "Content-Type, x-security-admin-key";
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

function unauthorizedResponse(origin = "") {
  return jsonResponse(origin, { ok: false, error: "not_found" }, 404);
}

function safeTimestamp(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) && num >= 0 ? Math.floor(num) : fallback;
}

function buildFlags(flags = {}) {
  return {
    freezeRegistrations: flags?.freezeRegistrations === true,
    disableProfileEdits: flags?.disableProfileEdits === true,
    lockAdminWrites: flags?.lockAdminWrites === true,
    readOnlyMode: flags?.readOnlyMode === true,
    disableUploads: flags?.disableUploads === true,
    forceCaptcha: flags?.forceCaptcha === true,
    lockdown: flags?.lockdown === true,
    lockAccount: flags?.lockAccount === true,
    killSessions: flags?.killSessions === true,
    blockActor: flags?.blockActor === true
  };
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

async function logContainmentState({
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
      await logContainmentState({
        env,
        type: "containment_state_forbidden_origin",
        level: "warning",
        request,
        actor,
        message: "Forbidden origin for containment state endpoint.",
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
      await logContainmentState({
        env,
        type: "containment_state_forbidden_host",
        level: "warning",
        request,
        actor,
        message: "Forbidden host for containment state endpoint.",
        metadata: { host }
      });

      return jsonResponse(
        origin,
        buildBlockedResponse("Forbidden host.", { action: "block" }),
        403
      );
    }

    const configuredAdminKey = safeString(
      env?.SECURITY_ADMIN_API_KEY || "",
      MAX_ADMIN_KEY_LENGTH
    );
    const providedAdminKey = safeString(
      request.headers.get("x-security-admin-key") || "",
      MAX_ADMIN_KEY_LENGTH
    );

    if (!configuredAdminKey) {
      await logContainmentState({
        env,
        type: "containment_state_misconfigured",
        level: "critical",
        request,
        actor,
        message: "SECURITY_ADMIN_API_KEY is missing for containment state endpoint."
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
        key: `containment-state:${actor.actorKey}`,
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

    if (finalAction === "block" || finalAction === "challenge") {
      await logContainmentState({
        env,
        type:
          finalAction === "block"
            ? "containment_state_blocked"
            : "containment_state_challenged",
        level: "warning",
        request,
        actor,
        message:
          finalAction === "block"
            ? "Containment state endpoint blocked by orchestrator."
            : "Containment state endpoint challenged by orchestrator.",
        metadata: {
          finalAction,
          riskScore: security?.risk?.riskScore || 0
        }
      });

      return unauthorizedResponse(origin);
    }

    if (!timingSafeEqual(providedAdminKey, configuredAdminKey)) {
      await logContainmentState({
        env,
        type: "containment_state_unauthorized",
        level: "warning",
        request,
        actor,
        message: "Unauthorized attempt to access containment state endpoint."
      });

      return unauthorizedResponse(origin);
    }

    const state = await getContainmentState(env);

    const payload = {
      success: true,
      mode: safeString(state?.mode || "normal", 30).toLowerCase(),
      updatedAt: safeTimestamp(state?.updatedAt, 0),
      expiresAt: safeTimestamp(state?.expiresAt, 0),
      flags: buildFlags(state?.flags || {})
    };

    await logContainmentState({
      env,
      type: "containment_state_accessed",
      level: "info",
      request,
      actor,
      message: "Containment state endpoint accessed successfully.",
      metadata: {
        mode: payload.mode
      }
    });

    return jsonResponse(origin, payload, 200);
  } catch (error) {
    try {
      await logContainmentState({
        env,
        type: "containment_state_error",
        level: "error",
        request,
        actor,
        message: "Failed to fetch containment state.",
        metadata: {
          error: error instanceof Error ? error.message : "unknown_error"
        }
      });
    } catch {}

    return jsonResponse(
      origin,
      {
        success: false,
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
