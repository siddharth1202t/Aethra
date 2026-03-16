import { getContainmentState } from "./_security-containment.js";
import {
  buildMethodNotAllowedResponse,
  safeString
} from "./_api-security.js";

const ROUTE = "/api/security-containment-state";

const ALLOWED_ORIGINS = new Set([
  "https://aethra-gules.vercel.app",
  "https://aethra-hb2h.vercel.app"
]);

function normalizeOrigin(origin = "") {
  return safeString(origin || "", 200).trim().toLowerCase();
}

function isOriginAllowed(origin = "") {
  return ALLOWED_ORIGINS.has(normalizeOrigin(origin));
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
      mode: safeString(state.mode || "normal", 30),
      updatedAt: Number(state.updatedAt || 0),
      expiresAt: Number(state.expiresAt || 0),
      flags: {
        freezeRegistrations: state?.flags?.freezeRegistrations === true,
        disableProfileEdits: state?.flags?.disableProfileEdits === true,
        lockAdminWrites: state?.flags?.lockAdminWrites === true,
        readOnlyMode: state?.flags?.readOnlyMode === true,
        disableUploads: state?.flags?.disableUploads === true,
        forceCaptcha: state?.flags?.forceCaptcha === true
      }
    });
  } catch (error) {
    console.error("Containment state API error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error.",
      route: ROUTE
    });
  }
}
