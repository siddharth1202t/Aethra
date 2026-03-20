function clampNumber(value, min = 0, max = 100) {
  const num = Number(value);
  if (!Number.isFinite(num)) return min;
  return Math.min(max, Math.max(min, num));
}

function normalizeMode(mode = "normal") {
  const allowed = new Set(["normal", "elevated", "defense", "lockdown"]);
  const safeMode = String(mode || "").trim().toLowerCase();
  return allowed.has(safeMode) ? safeMode : "normal";
}

function normalizeHealth(mode, threatPressure) {
  if (mode === "lockdown" || threatPressure >= 85) {
    return "critical";
  }

  if (mode === "defense" || threatPressure >= 60) {
    return "stressed";
  }

  if (mode === "elevated" || threatPressure >= 30) {
    return "guarded";
  }

  return "good";
}

export function buildSecurityStatus({
  adaptiveMode = "normal",
  threatPressure = 0,
  activeThreats = 0,
  containment = {},
  timestamp = Date.now()
} = {}) {
  const safeMode = normalizeMode(adaptiveMode);
  const safeThreatPressure = clampNumber(threatPressure, 0, 100);
  const safeActiveThreats = Math.max(0, Math.floor(Number(activeThreats) || 0));

  return {
    ok: true,
    timestamp: new Date(timestamp).toISOString(),
    mode: safeMode,
    threatPressure: safeThreatPressure,
    activeThreats: safeActiveThreats,
    systemHealth: normalizeHealth(safeMode, safeThreatPressure),
   containment: {
      mode: String(containment?.mode || "normal").slice(0, 30),
      freezeRegistrations: containment?.flags?.freezeRegistrations === true,
      disableProfileEdits: containment?.flags?.disableProfileEdits === true,
      lockAdminWrites: containment?.flags?.lockAdminWrites === true,
      disableUploads: containment?.flags?.disableUploads === true,
      forceCaptcha: containment?.flags?.forceCaptcha === true,
      readOnlyMode: containment?.flags?.readOnlyMode === true,
      lockdown: containment?.flags?.lockdown === true
   }
  };
}
