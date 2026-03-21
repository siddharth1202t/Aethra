import { getContainmentState } from "./_security-containment.js";
import {
  buildMethodNotAllowedResponse,
  safeString
} from "./_api-security.js";

const ALLOWED_ORIGINS = new Set([
  "127.0.0.1",
  "https://aethra-hb2h.vercel.app",
  "localhost"
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

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json(buildMethodNotAllowedResponse());
  }

  try {
    const origin = normalizeOrigin(req?.headers?.origin || "");

    if (origin && !isOriginAllowed(origin)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden origin."
      });
    }

    const state = await getContainmentState();

    return res.status(200).json({
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
    });
  } catch (error) {
    console.error("Containment state API error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error."
    });
  }
}
