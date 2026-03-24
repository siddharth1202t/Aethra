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

const PRIMARY_DOMAIN = "aethra-c46.pages.dev";

/* ---------------- SMART VALIDATION ---------------- */

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
  return safeString(ip || "0.0.0.0", 100)
    .replace(/[^a-fA-F0-9:.,]/g, "")
    .slice(0, 100) || "0.0.0.0";
}

function isLocal(origin) {
  return (
    origin.startsWith("http://localhost") ||
    origin.startsWith("http://127.0.0.1")
  );
}

function isPagesDev(originOrHost) {
  return safeString(originOrHost || "", 300).toLowerCase().endsWith(".pages.dev");
}

function isOriginAllowed(origin = "") {
  const normalized = normalizeOrigin(origin);
  if (!normalized) return false;

  if (isLocal(normalized)) return true;
  if (isPagesDev(normalized)) return true;
  if (normalized === `https://${PRIMARY_DOMAIN}`) return true;

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

/* ---------------- HELPERS ---------------- */

function getClientIp(request) {
  return normalizeIp(
    request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-forwarded-for")?.split(",")[0] ||
      request.headers.get("x-real-ip") ||
      "0.0.0.0"
  );
}

function getRequestHost(request) {
  return normalizeHostname(
    (request.headers.get("host") || "").split(":")[0]
  );
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
    "content-type": "application/json"
  };
}

function jsonResponse(origin, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: buildCorsHeaders(origin)
  });
}

function buildJsonError(origin, status, message) {
  return jsonResponse(origin, { success: false, message }, status);
}

function extractTurnstileToken(body = {}) {
  return safeString(
    body.token ||
      body.turnstileToken ||
      body["cf-turnstile-response"] ||
      "",
    MAX_TOKEN_LENGTH
  );
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
  const host = getRequestHost(request);

  if (!isJsonContentType(request)) {
    return buildJsonError(origin, 415, "Invalid content type.");
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_CONTENT_LENGTH_BYTES) {
    return buildJsonError(origin, 413, "Request body too large.");
  }

  if (!isOriginAllowed(origin)) {
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

  if (security?.risk?.finalAction === "block") {
    await writeSecurityLog({
      env,
      type: "turnstile_request_blocked",
      level: "warning",
      message: "Turnstile verification request blocked by security system",
      ip: actor.ip,
      route: ROUTE,
      metadata: {
        riskScore: security?.risk?.riskScore || 0
      }
    });

    return jsonResponse(
      origin,
      buildBlockedResponse("Suspicious request blocked.", { action: "block" }),
      403
    );
  }

  const token = extractTurnstileToken(body);
  if (!token) {
    return buildJsonError(origin, 400, "Missing captcha token.");
  }

  const secret = safeString(env.TURNSTILE_SECRET_KEY || "");
  if (!secret) {
    return buildJsonError(origin, 500, "Server misconfiguration.");
  }

  const ip = getClientIp(request);

  let data;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TURNSTILE_TIMEOUT_MS);

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

    clearTimeout(timeout);

    if (!res.ok) {
      const errorText = await res.text().catch(() => "");
      await writeSecurityLog({
        env,
        type: "turnstile_upstream_failed",
        level: "error",
        message: "Turnstile upstream verification request failed",
        ip,
        route: ROUTE,
        metadata: {
          status: res.status,
          response: safeString(errorText, 300)
        }
      });

      return buildJsonError(origin, 502, "Verification failed.");
    }

    data = await res.json();
  } catch (err) {
    await writeSecurityLog({
      env,
      type: "turnstile_error",
      level: "error",
      message: safeString(err?.message || "Turnstile request failed", 300),
      ip,
      route: ROUTE
    });

    return buildJsonError(origin, 502, "Verification failed.");
  }

  if (!data.success) {
    await writeSecurityLog({
      env,
      type: "turnstile_failed",
      level: "warning",
      message: "Captcha failed",
      ip,
      route: ROUTE,
      metadata: {
        errors: Array.isArray(data["error-codes"]) ? data["error-codes"] : []
      }
    });

    return buildJsonError(origin, 400, "Captcha verification failed.");
  }

  if (data.hostname && !isExpectedHostname(data.hostname)) {
    await writeSecurityLog({
      env,
      type: "turnstile_hostname_mismatch",
      level: "warning",
      message: "Turnstile hostname mismatch",
      ip,
      route: ROUTE,
      metadata: {
        hostname: safeString(data.hostname, 200)
      }
    });

    return buildJsonError(origin, 400, "Hostname mismatch.");
  }

  return jsonResponse(origin, {
    success: true,
    action: "allow"
  });
}

export async function onRequest(context) {
  if (context.request.method === "OPTIONS") {
    return onRequestOptions(context);
  }

  if (context.request.method === "POST") {
    return onRequestPost(context);
  }

  return jsonResponse(
    context.request.headers.get("origin") || "",
    buildMethodNotAllowedResponse(),
    405
  );
}
