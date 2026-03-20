function clampNumber(value, min = 0, max = 100) {
  const num = Number(value);
  if (!Number.isFinite(num)) return min;
  return Math.min(max, Math.max(min, num));
}

function safeInt(value, fallback = 0, min = 0, max = 1_000_000) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num)) return fallback;
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

function calculateThreatPressure({
  mode = "normal",
  counters = {}
} = {}) {
  const totalSignals = safeInt(counters.totalSignals, 0, 0, 1_000_000);
  const criticalSignals = safeInt(counters.criticalSignals, 0, 0, 1_000_000);
  const blockSignals = safeInt(counters.blockSignals, 0, 0, 1_000_000);
  const challengeSignals = safeInt(counters.challengeSignals, 0, 0, 1_000_000);
  const repeatedOffenderSignals = safeInt(counters.repeatedOffenderSignals, 0, 0, 1_000_000);
  const lockdownTriggers = safeInt(counters.lockdownTriggers, 0, 0, 1_000_000);
  const highRiskStateSignals = safeInt(counters.highRiskStateSignals, 0, 0, 1_000_000);
  const routePressureSignals = safeInt(counters.routePressureSignals, 0, 0, 1_000_000);

  let pressure = 0;

  pressure += Math.min(20, totalSignals * 2);
  pressure += Math.min(20, criticalSignals * 5);
  pressure += Math.min(15, blockSignals * 4);
  pressure += Math.min(10, challengeSignals * 2);
  pressure += Math.min(15, repeatedOffenderSignals * 4);
  pressure += Math.min(10, lockdownTriggers * 5);
  pressure += Math.min(5, highRiskStateSignals * 2);
  pressure += Math.min(5, routePressureSignals * 2);

  if (mode === "elevated") pressure = Math.max(pressure, 35);
  if (mode === "defense") pressure = Math.max(pressure, 65);
  if (mode === "lockdown") pressure = Math.max(pressure, 90);

  return clampNumber(pressure, 0, 100);
}

export function buildSecurityStatus({
  adaptiveState = {},
  threatSnapshot = {},
  containment = {},
  timestamp = Date.now()
} = {}) {
  const safeMode = normalizeMode(adaptiveState.mode || "normal");
  const counters =
    adaptiveState && typeof adaptiveState.counters === "object"
      ? adaptiveState.counters
      : {};

  const threatPressure = calculateThreatPressure({
    mode: safeMode,
    counters
  });

  const activeThreats =
    safeInt(counters.criticalSignals, 0, 0, 1_000_000) +
    safeInt(counters.blockSignals, 0, 0, 1_000_000) +
    safeInt(counters.repeatedOffenderSignals, 0, 0, 1_000_000) +
    safeInt(threatSnapshot.activeThreats, 0, 0, 1_000_000);

  return {
    ok: true,
    timestamp: new Date(timestamp).toISOString(),
    mode: safeMode,
    threatPressure,
    activeThreats,
    systemHealth: normalizeHealth(safeMode, threatPressure),
    adaptive: {
      updatedAt: safeInt(adaptiveState.updatedAt, 0, 0, Date.now() + 60_000),
      windowStartedAt: safeInt(adaptiveState.windowStartedAt, 0, 0, Date.now() + 60_000),
      lastReason: String(adaptiveState.lastReason || "stable_activity").slice(0, 200)
    },
    counters: {
      totalSignals: safeInt(counters.totalSignals, 0, 0, 1_000_000),
      criticalSignals: safeInt(counters.criticalSignals, 0, 0, 1_000_000),
      blockSignals: safeInt(counters.blockSignals, 0, 0, 1_000_000),
      challengeSignals: safeInt(counters.challengeSignals, 0, 0, 1_000_000),
      repeatedOffenderSignals: safeInt(counters.repeatedOffenderSignals, 0, 0, 1_000_000),
      lockdownTriggers: safeInt(counters.lockdownTriggers, 0, 0, 1_000_000),
      highRiskStateSignals: safeInt(counters.highRiskStateSignals, 0, 0, 1_000_000),
      routePressureSignals: safeInt(counters.routePressureSignals, 0, 0, 1_000_000)
    },
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
