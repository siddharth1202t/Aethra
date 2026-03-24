const MAX_COUNTER_VALUE = 1_000_000;
const MAX_EVENT_WINDOW_SIZE = 1000;

const ALLOWED_MODES = new Set([
  "normal",
  "elevated",
  "defense",
  "lockdown"
]);

function safeInt(value, fallback = 0, min = 0, max = MAX_COUNTER_VALUE) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeString(value, maxLength = 100) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function normalizeMode(mode = "normal") {
  const normalized = safeString(mode || "normal", 30).toLowerCase();
  return ALLOWED_MODES.has(normalized) ? normalized : "normal";
}

function calculateThreatPressureFromCounters(counters = {}, mode = "normal") {
  const totalSignals = safeInt(counters.totalSignals, 0);
  const criticalSignals = safeInt(counters.criticalSignals, 0);
  const blockSignals = safeInt(counters.blockSignals, 0);
  const challengeSignals = safeInt(counters.challengeSignals, 0);
  const repeatedOffenderSignals = safeInt(counters.repeatedOffenderSignals, 0);
  const lockdownTriggers = safeInt(counters.lockdownTriggers, 0);
  const highRiskStateSignals = safeInt(counters.highRiskStateSignals, 0);
  const routePressureSignals = safeInt(counters.routePressureSignals, 0);

  const burstSignals = safeInt(counters.burstSignals, 0);
  const coordinatedAttackSignals = safeInt(counters.coordinatedAttackSignals, 0);
  const breachAttemptSignals = safeInt(counters.breachAttemptSignals, 0);
  const exploitAttemptSignals = safeInt(counters.exploitAttemptSignals, 0);

  let pressure = 0;

  pressure += Math.min(15, totalSignals * 2);
  pressure += Math.min(15, criticalSignals * 4);
  pressure += Math.min(10, blockSignals * 3);
  pressure += Math.min(8, challengeSignals * 2);
  pressure += Math.min(10, repeatedOffenderSignals * 3);
  pressure += Math.min(8, lockdownTriggers * 5);
  pressure += Math.min(5, highRiskStateSignals * 2);
  pressure += Math.min(5, routePressureSignals * 2);

  pressure += Math.min(8, burstSignals * 3);
  pressure += Math.min(10, coordinatedAttackSignals * 4);
  pressure += Math.min(12, breachAttemptSignals * 5);
  pressure += Math.min(12, exploitAttemptSignals * 5);

  if (mode === "elevated") pressure = Math.max(pressure, 35);
  if (mode === "defense") pressure = Math.max(pressure, 65);
  if (mode === "lockdown") pressure = Math.max(pressure, 90);

  return Math.min(100, Math.max(0, pressure));
}

function createEmptySeverityCounts() {
  return {
    info: 0,
    warning: 0,
    error: 0,
    critical: 0
  };
}

function createEmptyActionCounts() {
  return {
    allow: 0,
    challenge: 0,
    throttle: 0,
    block: 0,
    contain: 0,
    observe: 0
  };
}

function createEmptySignalCounts() {
  return {
    exploitSignals: 0,
    breachSignals: 0,
    replaySignals: 0,
    coordinatedSignals: 0
  };
}

function normalizeCounters(input = {}) {
  const counters = isPlainObject(input) ? input : {};

  return {
    totalSignals: safeInt(counters.totalSignals, 0),
    criticalSignals: safeInt(counters.criticalSignals, 0),
    blockSignals: safeInt(counters.blockSignals, 0),
    challengeSignals: safeInt(counters.challengeSignals, 0),
    repeatedOffenderSignals: safeInt(counters.repeatedOffenderSignals, 0),
    lockdownTriggers: safeInt(counters.lockdownTriggers, 0),
    highRiskStateSignals: safeInt(counters.highRiskStateSignals, 0),
    routePressureSignals: safeInt(counters.routePressureSignals, 0),

    burstSignals: safeInt(counters.burstSignals, 0),
    coordinatedAttackSignals: safeInt(counters.coordinatedAttackSignals, 0),
    breachAttemptSignals: safeInt(counters.breachAttemptSignals, 0),
    exploitAttemptSignals: safeInt(counters.exploitAttemptSignals, 0)
  };
}

function normalizeEventList(events) {
  return Array.isArray(events) ? events : [];
}

function normalizeTimestamp(timestamp = Date.now()) {
  const parsed = Number(timestamp);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : Date.now();
}

export function buildSecurityMetrics({
  adaptiveState = {},
  containmentState = {},
  events = [],
  timestamp = Date.now()
} = {}) {
  const safeAdaptiveState = isPlainObject(adaptiveState) ? adaptiveState : {};
  const safeContainmentState = isPlainObject(containmentState)
    ? containmentState
    : {};
  const safeEvents = normalizeEventList(events);

  const mode = normalizeMode(safeAdaptiveState.mode || "normal");
  const containmentMode = normalizeMode(safeContainmentState.mode || "normal");
  const counters = normalizeCounters(
    isPlainObject(safeAdaptiveState.counters) ? safeAdaptiveState.counters : {}
  );

  const severityCounts = createEmptySeverityCounts();
  const actionCounts = createEmptyActionCounts();
  const signalCounts = createEmptySignalCounts();

  let recentHighSeverityCount = 0;
  let containmentEventCount = 0;
  let unauthorizedAdminAttempts = 0;
  let criticalEventCluster = 0;

  for (const event of safeEvents) {
    const severity = safeString(event?.severity || "", 20).toLowerCase();
    const action = safeString(event?.action || "", 20).toLowerCase();
    const type = safeString(event?.type || "", 80).toLowerCase();

    if (severity in severityCounts) {
      severityCounts[severity] += 1;
    }

    if (action in actionCounts) {
      actionCounts[action] += 1;
    }

    if (
      severity === "warning" ||
      severity === "error" ||
      severity === "critical"
    ) {
      recentHighSeverityCount += 1;
    }

    if (severity === "critical") {
      criticalEventCluster += 1;
    }

    if (type.startsWith("containment_") || type.startsWith("actor_containment_")) {
      containmentEventCount += 1;
    }

    if (
      type === "admin_endpoint_unauthorized" ||
      type === "admin_access_denied" ||
      type === "developer_access_denied"
    ) {
      unauthorizedAdminAttempts += 1;
    }

    if (type.includes("exploit")) {
      signalCounts.exploitSignals += 1;
    }

    if (type.includes("breach")) {
      signalCounts.breachSignals += 1;
    }

    if (type.includes("replay")) {
      signalCounts.replaySignals += 1;
    }

    if (type.includes("coordinated")) {
      signalCounts.coordinatedSignals += 1;
    }
  }

  const threatPressure = calculateThreatPressureFromCounters(counters, mode);
  const normalizedTimestamp = normalizeTimestamp(timestamp);

  const criticalAttackLikely =
    mode === "lockdown" ||
    counters.breachAttemptSignals > 0 ||
    counters.exploitAttemptSignals > 0 ||
    signalCounts.breachSignals > 0 ||
    signalCounts.exploitSignals > 0 ||
    criticalEventCluster >= 3;

  return {
    ok: true,
    timestamp: new Date(normalizedTimestamp).toISOString(),
    mode,
    containmentMode,
    threatPressure,
    eventWindowSize: safeInt(safeEvents.length, 0, 0, MAX_EVENT_WINDOW_SIZE),
    counters,
    eventCounts: {
      bySeverity: severityCounts,
      byAction: actionCounts,
      bySignal: signalCounts
    },
    highlights: {
      recentHighSeverityCount,
      containmentEventCount,
      unauthorizedAdminAttempts,
      forceCaptchaEnabled: safeContainmentState?.flags?.forceCaptcha === true,
      lockdownActive: safeContainmentState?.flags?.lockdown === true,
      readOnlyMode: safeContainmentState?.flags?.readOnlyMode === true,
      criticalAttackLikely
    }
  };
}
