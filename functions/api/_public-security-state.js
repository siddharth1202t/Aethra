import { safeString } from "./_api-security.js";

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

function derivePublicMode(flags) {
  if (flags?.readOnlyMode) return "restricted";
  if (flags?.freezeRegistrations || flags?.disableUploads) return "elevated";
  return "normal";
}

export function buildPublicSecurityState(containmentState = {}) {
  const flags = buildPublicFlags(containmentState?.flags || {});

  return {
    success: true,
    action: "allow",
    mode: safeString(derivePublicMode(flags), 30).toLowerCase(),
    updatedAt: safeTimestamp(containmentState?.updatedAt, 0),
    expiresAt: safeTimestamp(containmentState?.expiresAt, 0),
    flags
  };
}
