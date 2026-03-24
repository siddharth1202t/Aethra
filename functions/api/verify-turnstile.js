import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import {
  safeString,
  sanitizeBody,
  buildBlockedResponse,
  buildMethodNotAllowedResponse
} from "./_api-security.js";

const ROUTE = "/api/verify-turnstile";
const TURNSTILE_VERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";

const TURNSTILE_TIMEOUT_MS = 8000;
const MAX_BODY_KEYS = 25;
const MAX_CONTENT_LENGTH_BYTES = 12 * 1024;
const MAX_TOKEN_LENGTH = 5000;
const MIN_TOKEN_LENGTH = 20;

const PRIMARY_DOMAIN = "aethra-c46.pages.dev";

/* ---------------- VALIDATION / NORMALIZATION ---------------- */

function normalizeOrigin(origin = "") {
  try {
    return new URL(origin).origin.toLowerCase();
  } catch {
    return "";
  }
}

function normalizeHostname(hostname = "") {
  return safeString(hostname, 200).trim().toLowerCase();
}

function normalizeIp(ip = "") {
  return (
    safeString(ip || "0.0.0.0", 100)
      .replace(/[^a-fA-F0-9:.,]/g, "")
      .slice(0, 100) || "0.0.0.0"
  );
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

function getClientIp(request) {
  return normalizeIp(
    request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-forwarded-for")?.split(",")[0] ||
      request.headers.get("x-real-ip") ||
      "0.0.0.0"
  );
}

function getRequestHost(request) {
  return normalizeHostname((request.headers.get("host") || "").split(":")[0]);
}

function isJsonContentType(request) {
  return (request.headers.get("content-type") || "")
    .toLowerCase()
    .includes("application/json");
}

function buildCorsHeaders(origin = "") {
  const normalized = normalizeOrigin(origin);
  const allowed = isOriginAllowed(normalized) ? normalized : "null";

  return {
    "access-control-allow-origin": allowed,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "content-type": "application/json",
    "cache-control": "no-store"
  };
}

function jsonResponse(origin, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: buildCorsHeaders(origin)
  });
}

function buildJsonError(origin, status, message, extra = {}) {
  return jsonResponse(origin, { success: false, message, ...extra }, status);
}

function extractTurnstileToken(body = {}) {
  return safeString(
    body.token ||
      body.turnstileToken ||
      body["cf-turnstile-response"] ||
      "",
    MAX_TOKEN_LENGTH
  ).trim();
}

function isValidTurnstileToken(token = "") {
  if (!token) return false;
  if (token.length < MIN_TOKEN_LENGTH || token.length > MAX_TOKEN_LENGTH) {
    return false;
  }

  // Conservative validation: allow common token chars only.
  return /^[A-Za-z0-9._\-]+$/.test(token);
}

function normalizeErrorCodes(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => safeString(item, 100)).filter(Boolean).slice(0, 10);
}

function extractActionFromSecurity(security) {
  return safeString(security?.risk?.finalAction || "allow", 50).toLowerCase();
}

async function logTurnstileEvent({
  env,
  type,
  level,
  message,
  actor,
  request,
  metadata = {}
}) {
  await writeSecurityLog({
    env,
    type,
    level,
    message,
    ip: actor?.ip || getClientIp(request),
    route: ROUTE,
    userId: actor?.userId || null,
    sessionId: actor?.sessionId || null,
    metadata: {
      actorKey: actor?.actorKey || null,
      routeKey: actor?.routeKey || null,
      host: getRequestHost(request),
      origin: normalizeOrigin(request.headers.get("origin") || ""),
      ...metadata
    }
  });
}

/* ---------------- HANDLERS ---------------- */

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("origin") || "";
  return new Response(null, {
    status: 204,
    headers: buildCorsHeaders(origin)
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const origin = request.headers.get("origin") || "";
  const normalizedOrigin = normalizeOrigin(origin);
  const host = getRequestHost(request);
  const ip = getClientIp(request);

  if (!isJsonContentType(request)) {
    return buildJsonError(origin, 415, "Invalid content type.");
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return buildJsonError(origin, 413, "Request body too large.");
  }

  if (!isOriginAllowed(normalizedOrigin)) {
    return jsonResponse(
      origin,
      buildBlockedResponse("Forbidden origin.", { action: "block" }),
      403
    );
  }

  if (!isExpectedHostname(host)) {
    return jsonResponse(
      origin,
      buildBlockedResponse("Forbidden host.", { action: "block" }),
      403
    );
  }

  let body;
  try {
    body = sanitizeBody(await request.json(), MAX_BODY_KEYS);
  } catch {
    return buildJsonError(origin, 400, "Invalid JSON.");
  }

  const actor = createActorContext({
    req: request,
    body,
    route: ROUTE
  });

  const secret = safeString(env?.TURNSTILE_SECRET_KEY || "", 300).trim();
  if (!secret) {
    await logTurnstileEvent({
      env,
      type: "turnstile_misconfigured",
      level: "error",
      message: "TURNSTILE_SECRET_KEY is missing",
      actor,
      request
    });

    return buildJsonError(origin, 500, "Server misconfiguration.");
  }

  const security = await runSecurityOrchestrator({
    env,
    req: request,
    body,
    route: ROUTE,
    context: {
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId
    },
    rateLimitConfig: {
      key: `turnstile:${actor.actorKey}`,
      limit: 20,
      windowMs: 60 * 1000
    },
    abuseSuccess: true,
    containmentConfig: {
      isWriteAction: true,
      actionType: "captcha_verify",
      routeSensitivity: "critical"
    }
  });

  const securityAction = extractActionFromSecurity(security);

  if (securityAction === "block") {
    await logTurnstileEvent({
      env,
      type: "turnstile_request_blocked",
      level: "warning",
      message: "Turnstile verification request blocked by security system",
      actor,
      request,
      metadata: {
        riskScore: security?.risk?.riskScore || 0,
        finalAction: securityAction
      }
    });

    return jsonResponse(
      origin,
      buildBlockedResponse("Suspicious request blocked.", { action: "block" }),
      403
    );
  }

  if (securityAction === "challenge") {
    await logTurnstileEvent({
      env,
      type: "turnstile_request_challenged",
      level: "warning",
      message: "Turnstile verification request challenged by security system",
      actor,
      request,
      metadata: {
        riskScore: security?.risk?.riskScore || 0,
        finalAction: securityAction
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

  const token = extractTurnstileToken(body);
  if (!isValidTurnstileToken(token)) {
    await logTurnstileEvent({
      env,
      type: "turnstile_token_invalid",
      level: "warning",
      message: "Invalid or malformed Turnstile token",
      actor,
      request,
      metadata: {
        tokenLength: token?.length || 0
      }
    });

    return buildJsonError(origin, 400, "Missing or invalid captcha token.");
  }

  let data = null;
  let upstreamStatus = null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TURNSTILE_TIMEOUT_MS);

  try {
    const res = await fetch(TURNSTILE_VERIFY_URL, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        secret,
        response: token,
        remoteip: ip
      }),
      signal: controller.signal
    });

    upstreamStatus = res.status;

    if (!res.ok) {
      const errorText = await res.text().catch(() => "");
      await logTurnstileEvent({
        env,
        type: "turnstile_upstream_failed",
        level: "error",
        message: "Turnstile upstream verification request failed",
        actor,
        request,
        metadata: {
          upstreamStatus: res.status,
          upstreamBody: safeString(errorText, 300)
        }
      });

      return buildJsonError(origin, 502, "Verification failed.");
    }

    data = await res.json().catch(() => null);
  } catch (err) {
    const isAbort = err?.name === "AbortError";

    await logTurnstileEvent({
      env,
      type: isAbort ? "turnstile_timeout" : "turnstile_error",
      level: "error",
      message: safeString(
        isAbort
          ? "Turnstile verification timed out"
          : err?.message || "Turnstile request failed",
        300
      ),
      actor,
      request,
      metadata: {
        upstreamStatus
      }
    });

    return buildJsonError(
      origin,
      502,
      isAbort ? "Verification timed out." : "Verification failed."
    );
  } finally {
    clearTimeout(timeout);
  }

  if (!data || typeof data !== "object") {
    await logTurnstileEvent({
      env,
      type: "turnstile_invalid_response",
      level: "error",
      message: "Turnstile returned an invalid response payload",
      actor,
      request,
      metadata: {
        upstreamStatus
      }
    });

    return buildJsonError(origin, 502, "Verification failed.");
  }

  const success = data.success === true;
  const responseHostname = normalizeHostname(data.hostname || "");
  const errorCodes = normalizeErrorCodes(data["error-codes"]);

  if (!success) {
    await logTurnstileEvent({
      env,
      type: "turnstile_failed",
      level: "warning",
      message: "Captcha verification failed",
      actor,
      request,
      metadata: {
        errorCodes,
        upstreamStatus
      }
    });

    return buildJsonError(origin, 400, "Captcha verification failed.");
  }

  if (responseHostname && !isExpectedHostname(responseHostname)) {
    await logTurnstileEvent({
      env,
      type: "turnstile_hostname_mismatch",
      level: "warning",
      message: "Turnstile hostname mismatch",
      actor,
      request,
      metadata: {
        responseHostname,
        upstreamStatus
      }
    });

    return buildJsonError(origin, 400, "Hostname mismatch.");
  }

  await logTurnstileEvent({
    env,
    type: "turnstile_verified",
    level: "info",
    message: "Turnstile verification succeeded",
    actor,
    request,
    metadata: {
      responseHostname: responseHostname || null,
      upstreamStatus
    }
  });

  return jsonResponse(origin, {
    success: true,
    action: "allow"
  });
}

export async function onRequest(context) {
  const method = context.request.method;

  if (method === "OPTIONS") {
    return onRequestOptions(context);
  }

  if (method === "POST") {
    return onRequestPost(context);
  }

  return jsonResponse(
    context.request.headers.get("origin") || "",
    buildMethodNotAllowedResponse(),
    405
  );
}
