import { writeSecurityLog } from "./_security-log-writer.js";
import { createActorContext } from "./_actor-context.js";
import { runSecurityOrchestrator } from "./_security-orchestrator.js";
import {
  safeString,
  sanitizeBody,
  sanitizeMetadata,
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
const MAX_SESSION_ID_LENGTH = 120;

/* ---------------- CORE DOMAIN CONFIG ---------------- */

// 🔐 Your primary production domain
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

function isLocal(origin) {
  return (
    origin.startsWith("http://localhost") ||
    origin.startsWith("http://127.0.0.1")
  );
}

function isPagesDev(originOrHost) {
  return originOrHost.endsWith(".pages.dev");
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
  return (
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0] ||
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

/* ---------------- HANDLERS ---------------- */

export async function onRequestOptions(context) {
  const origin = context.request.headers.get("origin") || "";
  return new Response(null, {
    status: 204,
    headers: buildCorsHeaders(origin)
  });
}

export async function onRequestPost(context) {
  const request = context.request;
  const origin = request.headers.get("origin") || "";
  const host = getRequestHost(request);

  if (!isJsonContentType(request)) {
    return buildJsonError(origin, 415, "Invalid content type.");
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

  const token = safeString(body.token || "", MAX_TOKEN_LENGTH);
  if (!token) {
    return buildJsonError(origin, 400, "Missing captcha token.");
  }

  const ip = getClientIp(request);
  const secret = safeString(context.env.TURNSTILE_SECRET_KEY || "");

  if (!secret) {
    return buildJsonError(origin, 500, "Server misconfiguration.");
  }

  let data;
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
      })
    });

    data = await res.json();
  } catch (err) {
    await writeSecurityLog({
      type: "turnstile_error",
      level: "error",
      message: err.message
    });

    return buildJsonError(origin, 502, "Verification failed.");
  }

  if (!data.success) {
    await writeSecurityLog({
      type: "turnstile_failed",
      level: "warning",
      message: "Captcha failed",
      metadata: {
        errors: data["error-codes"]
      }
    });

    return buildJsonError(origin, 400, "Captcha verification failed.");
  }

  if (data.hostname && !isExpectedHostname(data.hostname)) {
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
