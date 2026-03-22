const MAX_COUNTER_VALUE = 1_000_000;
const MAX_TIMESTAMP_FUTURE_SKEW_MS = 60_000;
const TOTAL_SIGNAL_CAP = 2_000_000;

const ALLOWED_MODES = new Set(["normal", "elevated", "defense", "lockdown"]);

/* -------------------- CORE SAFETY -------------------- */

function isPlainObject(value) {
  if (Object.prototype.toString.call(value) !== "[object Object]") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

function sanitizeObject(obj) {
  if (!isPlainObject(obj)) return {};
  const clean = {};
  for (const key of Object.keys(obj)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    clean[key] = obj[key];
  }
  return clean;
}

function clampNumber(value, min = 0, max = 100) {
  const num = Number(value);
  return Number.isFinite(num) ? Math.min(max, Math.max(min, num)) : min;
}

function safeInt(value, fallback = 0, min = 0, max = MAX_COUNTER_VALUE) {
  const num = Math.floor(Number(value));
  return Number.isFinite(num) ? Math.min(max, Math.max(min, num)) : fallback;
}

function safeString(value, maxLength = 200) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function normalizeTimestamp(value, fallback = Date.now()) {
  return safeInt(value, fallback, 0, Date.now() + MAX_TIMESTAMP_FUTURE_SKEW_MS);
}

/* -------------------- NORMALIZATION -------------------- */

function normalizeMode(mode = "normal") {
  const safeMode = safeString(mode, 30).toLowerCase();
  return ALLOWED_MODES.has(safeMode) ? safeMode : "normal";
}

function normalizeCounters(input = {}) {
  const counters = sanitizeObject(input);

  const normalized = {
    totalSignals: safeInt(counters.totalSignals),
    criticalSignals: safeInt(counters.criticalSignals),
    blockSignals: safeInt(counters.blockSignals),
    challengeSignals: safeInt(counters.challengeSignals),
    repeatedOffenderSignals: safeInt(counters.repeatedOffenderSignals),
    lockdownTriggers: safeInt(counters.lockdownTriggers),
    highRiskStateSignals: safeInt(counters.highRiskStateSignals),
    routePressureSignals: safeInt(counters.routePressureSignals)
  };

  const totalSum = Object.values(normalized).reduce((a, b) => a + b, 0);
  if (totalSum > TOTAL_SIGNAL_CAP) {
    return null;
  }

  return normalized;
}

function normalizeContainment(containment = {}) {
  const safeContainment = sanitizeObject(containment);
  const flags = sanitizeObject(safeContainment.flags);

  return {
    mode: normalizeMode(safeContainment.mode),
    freezeRegistrations: flags.freezeRegistrations === true,
    disableProfileEdits: flags.disableProfileEdits === true,
    lockAdminWrites: flags.lockAdminWrites === true,
    disableUploads: flags.disableUploads === true,
    forceCaptcha: flags.forceCaptcha === true,
    readOnlyMode: flags.readOnlyMode === true,
    lockdown: flags.lockdown === true
  };
}

/* -------------------- THREAT ENGINE -------------------- */

function detectAnomaly(c) {
  const total = c.totalSignals + c.criticalSignals + c.blockSignals;
  if (total === 0) return false;
  return (c.criticalSignals / total) > 0.7;
}

function calculateThreatPressure(mode, counters, timestamp) {
  let pressure = 0;

  pressure += Math.min(20, counters.totalSignals * 2);
  pressure += Math.min(20, counters.criticalSignals * 5);
  pressure += Math.min(15, counters.blockSignals * 4);
  pressure += Math.min(10, counters.challengeSignals * 2);
  pressure += Math.min(15, counters.repeatedOffenderSignals * 4);
  pressure += Math.min(10, counters.lockdownTriggers * 5);
  pressure += Math.min(5, counters.highRiskStateSignals * 2);
  pressure += Math.min(5, counters.routePressureSignals * 2);

  if (mode === "elevated") pressure = Math.max(pressure, 35);
  if (mode === "defense") pressure = Math.max(pressure, 65);
  if (mode === "lockdown") pressure = Math.max(pressure, 90);

  if (detectAnomaly(counters)) {
    pressure = Math.max(pressure, 80);
  }

  const drift = Math.abs(Date.now() - timestamp);
  if (drift > 30_000) {
    pressure = Math.max(pressure, 70);
  }

  return clampNumber(pressure);
}

function normalizeHealth(mode, threatPressure) {
  if (mode === "lockdown" || threatPressure >= 85) return "critical";
  if (mode === "defense" || threatPressure >= 60) return "stressed";
  if (mode === "elevated" || threatPressure >= 30) return "guarded";
  return "good";
}

/* -------------------- FREEZE -------------------- */

function deepFreeze(obj) {
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const value = obj[key];
    if (
      value &&
      (typeof value === "object" || typeof value === "function") &&
      !Object.isFrozen(value)
    ) {
      deepFreeze(value);
    }
  }
  return obj;
}

/* -------------------- MAIN -------------------- */

export function buildSecurityStatus({
  adaptiveState = {},
  threatSnapshot = {},
  containment = {},
  timestamp = Date.now()
} = {}) {
  const safeAdaptiveState = sanitizeObject(adaptiveState);
  const safeThreatSnapshot = sanitizeObject(threatSnapshot);

  let mode = normalizeMode(safeAdaptiveState.mode);

  const counters = normalizeCounters(safeAdaptiveState.counters);
  if (!counters) {
    return deepFreeze({
      ok: false,
      error: "signal_overflow_detected"
    });
  }

  const normalizedTimestamp = normalizeTimestamp(timestamp);
  const normalizedContainment = normalizeContainment(containment);

  if (normalizedContainment.lockdown) {
    mode = "lockdown";
  }

  const threatPressure = calculateThreatPressure(
    mode,
    counters,
    normalizedTimestamp
  );

  const activeThreats =
    counters.criticalSignals +
    counters.blockSignals +
    counters.repeatedOffenderSignals +
    safeInt(safeThreatSnapshot.activeThreats);

  const response = {
    ok: true,
    timestamp: new Date(normalizedTimestamp).toISOString(),
    mode,
    threatPressure,
    activeThreats,
    systemHealth: normalizeHealth(mode, threatPressure),
    adaptive: {
      updatedAt: normalizeTimestamp(safeAdaptiveState.updatedAt, 0),
      windowStartedAt: normalizeTimestamp(
        safeAdaptiveState.windowStartedAt,
        0
      ),
      lastReason: safeString(
        safeAdaptiveState.lastReason || "stable_activity"
      )
    },
    counters,
    containment: normalizedContainment
  };

  return deepFreeze(response);
}