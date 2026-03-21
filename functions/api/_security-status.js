const MAX_COUNTER_VALUE = 1_000_000;
const MAX_TIMESTAMP_FUTURE_SKEW_MS = 60_000;

const ALLOWED_MODES = new Set([
  "normal",
  "elevated",
  "defense",
  "lockdown"
]);

function clampNumber(value, min = 0, max = 100) {
  const num = Number(value);
  if (!Number.isFinite(num)) return min;
  return Math.min(max, Math.max(min, num));
}

function safeInt(value, fallback = 0, min = 0, max = MAX_COUNTER_VALUE) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeString(value, maxLength = 200) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function normalizeMode(mode = "normal") {
  const safeMode = safeString(mode || "normal", 30).toLowerCase();
  return ALLOWED_MODES.has(safeMode) ? safeMode : "normal";
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

function normalizeTimestamp(value, fallback = Date.now()) {
  return safeInt(value, fallback, 0, Date.now() + MAX_TIMESTAMP_FUTURE_SKEW_MS);
}

function normalizeCounters(input = {}) {
  const counters = isPlainObject(input) ? input : {};

  return {
    totalSignals: safeInt(counters.totalSignals, 0, 0, MAX_COUNTER_VALUE),
    criticalSignals: safeInt(counters.criticalSignals, 0, 0, MAX_COUNTER_VALUE),
    blockSignals: safeInt(counters.blockSignals, 0, 0, MAX_COUNTER_VALUE),
    challengeSignals: safeInt(counters.challengeSignals, 0, 0, MAX_COUNTER_VALUE),
    repeatedOffenderSignals: safeInt(
      counters.repeatedOffenderSignals,
      0,
      0,
      MAX_COUNTER_VALUE
    ),
    lockdownTriggers: safeInt(counters.lockdownTriggers, 0, 0, MAX_COUNTER_VALUE),
    highRiskStateSignals: safeInt(
      counters.highRiskStateSignals,
      0,
      0,
      MAX_COUNTER_VALUE
    ),
    routePressureSignals: safeInt(
      counters.routePressureSignals,
      0,
      0,
      MAX_COUNTER_VALUE
    )
  };
}

function calculateThreatPressure({
  mode = "normal",
  counters = {}
} = {}) {
  const normalizedCounters = normalizeCounters(counters);

  let pressure = 0;

  pressure += Math.min(20, normalizedCounters.totalSignals * 2);
  pressure += Math.min(20, normalizedCounters.criticalSignals * 5);
  pressure += Math.min(15, normalizedCounters.blockSignals * 4);
  pressure += Math.min(10, normalizedCounters.challengeSignals * 2);
  pressure += Math.min(15, normalizedCounters.repeatedOffenderSignals * 4);
  pressure += Math.min(10, normalizedCounters.lockdownTriggers * 5);
  pressure += Math.min(5, normalizedCounters.highRiskStateSignals * 2);
  pressure += Math.min(5, normalizedCounters.routePressureSignals * 2);

  if (mode === "elevated") pressure = Math.max(pressure, 35);
  if (mode === "defense") pressure = Math.max(pressure, 65);
  if (mode === "lockdown") pressure = Math.max(pressure, 90);

  return clampNumber(pressure, 0, 100);
}

function normalizeContainment(containment = {}) {
  const safeContainment = isPlainObject(containment) ? containment : {};
  const flags = isPlainObject(safeContainment.flags) ? safeContainment.flags : {};

  return {
    mode: normalizeMode(safeContainment.mode || "normal"),
    freezeRegistrations: flags.freezeRegistrations === true,
    disableProfileEdits: flags.disableProfileEdits === true,
    lockAdminWrites: flags.lockAdminWrites === true,
    disableUploads: flags.disableUploads === true,
    forceCaptcha: flags.forceCaptcha === true,
    readOnlyMode: flags.readOnlyMode === true,
    lockdown: flags.lockdown === true
  };
}

export function buildSecurityStatus({
  adaptiveState = {},
  threatSnapshot = {},
  containment = {},
  timestamp = Date.now()
} = {}) {
  const safeAdaptiveState = isPlainObject(adaptiveState) ? adaptiveState : {};
  const safeThreatSnapshot = isPlainObject(threatSnapshot) ? threatSnapshot : {};

  const safeMode = normalizeMode(safeAdaptiveState.mode || "normal");
  const counters = normalizeCounters(
    isPlainObject(safeAdaptiveState.counters) ? safeAdaptiveState.counters : {}
  );

  const threatPressure = calculateThreatPressure({
    mode: safeMode,
    counters
  });

  const activeThreats =
    counters.criticalSignals +
    counters.blockSignals +
    counters.repeatedOffenderSignals +
    safeInt(safeThreatSnapshot.activeThreats, 0, 0, MAX_COUNTER_VALUE);

  const normalizedTimestamp = normalizeTimestamp(timestamp, Date.now());
  const normalizedContainment = normalizeContainment(containment);

  return {
    ok: true,
    timestamp: new Date(normalizedTimestamp).toISOString(),
    mode: safeMode,
    threatPressure,
    activeThreats,
    systemHealth: normalizeHealth(safeMode, threatPressure),
    adaptive: {
      updatedAt: normalizeTimestamp(safeAdaptiveState.updatedAt, 0),
      windowStartedAt: normalizeTimestamp(safeAdaptiveState.windowStartedAt, 0),
      lastReason: safeString(
        safeAdaptiveState.lastReason || "stable_activity",
        200
      )
    },
    counters,
    containment: normalizedContainment
  };
}
