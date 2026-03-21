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

export async function onRequestGet(context) {
  try {
    const origin = normalizeOrigin(context.request.headers.get("origin") || "");

    if (origin && !isOriginAllowed(origin)) {
      return new Response(
        JSON.stringify({
          success: false,
          message: "Forbidden origin."
        }),
        {
          status: 403,
          headers: {
            "content-type": "application/json"
          }
        }
      );
    }

    const state = await getContainmentState();

    return new Response(
      JSON.stringify({
        success: true,
        mode: safeString(state?.mode || "normal", 30).toLowerCase(),
        updatedAt: safeTimestamp(state?.updatedAt, 0),
        expiresAt: safeTimestamp(state?.expiresAt, 0),
        flags: {
          freezeRegistrations: state?.flags?.freezeRegistrations === true,
          disableProfileEdits: state?.flags?.disableProfileEdits === true,
          lockAdminWrites: state?.flags?.lockAdminWrites === true,
          readOnlyMode: state?.flags?.readOnlyMode === true,
          disableUploads: state?.flags?.disableUploads === true,
          forceCaptcha: state?.flags?.forceCaptcha === true,
          lockdown: state?.flags?.lockdown === true
        }
      }),
      {
        status: 200,
        headers: {
          "content-type": "application/json"
        }
      }
    );
  } catch (error) {
    console.error("Containment state API error:", error);

    return new Response(
      JSON.stringify({
        success: false,
        message: "Internal server error."
      }),
      {
        status: 500,
        headers: {
          "content-type": "application/json"
        }
      }
    );
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET, OPTIONS",
      "access-control-allow-headers": "Content-Type"
    }
  });
}

export async function onRequest(context) {
  if (context.request.method === "GET") {
    return onRequestGet(context);
  }

  if (context.request.method === "OPTIONS") {
    return onRequestOptions();
  }

  return new Response(
    JSON.stringify(buildMethodNotAllowedResponse()),
    {
      status: 405,
      headers: {
        "content-type": "application/json"
      }
    }
  );
}
