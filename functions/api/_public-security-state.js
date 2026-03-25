import { safeString, isPlainObject } from "./_api-security.js";

function safeTimestamp(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) && num >= 0 ? Math.floor(num) : fallback;
}

function buildPublicFlags(flags = {}) {
  const safeFlags = isPlainObject(flags) ? flags : {};

  return {
    freezeRegistrations: safeFlags.freezeRegistrations === true,
    disableProfileEdits: safeFlags.disableProfileEdits === true,
    readOnlyMode: safeFlags.readOnlyMode === true,
    disableUploads: safeFlags.disableUploads === true,
    forceCaptcha: safeFlags.forceCaptcha === true
  };
}

function derivePublicMode(flags) {
  if (flags?.readOnlyMode) return "restricted";
  if (
    flags?.freezeRegistrations ||
    flags?.disableUploads ||
    flags?.forceCaptcha
  ) {
    return "elevated";
  }
  return "normal";
}

function deepFreeze(obj, seen = new WeakSet()) {
  if (!obj || (typeof obj !== "object" && typeof obj !== "function")) {
    return obj;
  }

  if (seen.has(obj)) {
    return obj;
  }

  seen.add(obj);
  Object.freeze(obj);

  for (const key of Object.getOwnPropertyNames(obj)) {
    const value = obj[key];
    if (
      value &&
      (typeof value === "object" || typeof value === "function") &&
      !Object.isFrozen(value)
    ) {
      deepFreeze(value, seen);
    }
  }

  return obj;
}

export function buildPublicSecurityState(containmentState = {}) {
  const safeContainmentState = isPlainObject(containmentState)
    ? containmentState
    : {};

  const flags = buildPublicFlags(safeContainmentState.flags || {});

  const response = {
    success: true,
    action: "allow",
    mode: safeString(derivePublicMode(flags), 30).toLowerCase(),
    updatedAt: safeTimestamp(safeContainmentState.updatedAt, 0),
    expiresAt: safeTimestamp(safeContainmentState.expiresAt, 0),
    flags
  };

  return deepFreeze(response);
}
