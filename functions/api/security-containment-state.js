import { getContainmentState } from "./_security-containment.js";
import {
  buildMethodNotAllowedResponse,
  safeString
} from "./_api-security.js";

const ALLOWED_ORIGINS = new Set([
  "http://127.0.0.1:8080",
  "http://localhost:8080",
  "https://aethra-c46.pages.dev"
]);

function normalizeOrigin(origin = "") {
  const raw = safeString(origin || "", 200).trim();

  if (!raw) {
    return "";
  }

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(normalizeOrigin(origin));
}

function safeTimestamp(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) && num >= 0 ? Math.floor(num) : fallback;
}

function buildCorsHeaders(origin = "") {
  const normalizedOrigin = normalizeOrigin(origin);
  const allowOrigin = isOriginAllowed(normalizedOrigin) ? normalizedOrigin : "null";

  return {
    "access-control-allow-origin": allowOrigin,
    "access-control-allow-methods": "GET, OPTIONS",
    "access-control-allow-headers": "Content-Type",
    "cache-control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    pragma: "no-cache",
    expires: "0",
    vary: "Origin",
    "content-type": "application/json; charset=utf-8"
  };
}

function jsonResponse(origin, payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: buildCorsHeaders(origin)
  });
}

function buildFlags(flags = {}) {
  return {
    freezeRegistrations: flags?.freezeRegistrations === true,
    disableProfileEdits: flags?.disableProfileEdits === true,
    lockAdminWrites: flags?.lockAdminWrites === true,
    readOnlyMode: flags?.readOnlyMode === true,
    disableUploads: flags?.disableUploads === true,
    forceCaptcha: flags?.forceCaptcha === true,
    lockdown: flags?.lockdown === true
  };
}

export async function onRequestGet(context) {
  const origin = context.request.headers.get("origin") || "";

  try {
    const normalizedOrigin = normalizeOrigin(origin);

    if (normalizedOrigin && !isOriginAllowed(normalizedOrigin)) {
      return jsonResponse(
        origin,
        {
          success: false,
          message: "Forbidden origin."
        },
        403
      );
    }

    const state = await getContainmentState();

    return jsonResponse(origin, {
      success: true,
      mode: safeString(state?.mode || "normal", 30).toLowerCase(),
      updatedAt: safeTimestamp(state?.updatedAt, 0),
      expiresAt: safeTimestamp(state?.expiresAt, 0),
      flags: buildFlags(state?.flags || {})
    });
  } catch (error) {
    console.error("Containment state API error:", error);

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
    headers: buildCorsHeaders(origin)
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

  return jsonResponse(
    origin,
    buildMethodNotAllowedResponse(),
    405
  );
}
