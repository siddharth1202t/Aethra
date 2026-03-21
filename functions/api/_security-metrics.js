function safeInt(value, fallback = 0, min = 0, max = 1_000_000) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeString(value, maxLength = 100) {
  return String(value || "").trim().slice(0, maxLength);
}

function normalizeMode(mode = "normal") {
  const allowed = new Set(["normal", "elevated", "defense", "lockdown"]);
  const normalized = safeString(mode || "normal", 30).toLowerCase();
  return allowed.has(normalized) ? normalized : "normal";
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

  return Math.min(100, Math.max(0, pressure));
}

function createEmptyCounts() {
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

export function buildSecurityMetrics({
  adaptiveState = {},
  containmentState = {},
  events = [],
  timestamp = Date.now()
} = {}) {
  const mode = normalizeMode(adaptiveState?.mode || "normal");
  const counters =
    adaptiveState && typeof adaptiveState.counters === "object"
      ? adaptiveState.counters
      : {};

  const severityCounts = createEmptyCounts();
  const actionCounts = createEmptyActionCounts();

  let recentHighSeverityCount = 0;
  let containmentEventCount = 0;
  let unauthorizedAdminAttempts = 0;

  for (const event of Array.isArray(events) ? events : []) {
    const severity = safeString(event?.severity || "", 20).toLowerCase();
    const action = safeString(event?.action || "", 20).toLowerCase();
    const type = safeString(event?.type || "", 80).toLowerCase();

    if (severity in severityCounts) {
      severityCounts[severity] += 1;
    }

    if (action in actionCounts) {
      actionCounts[action] += 1;
    }

    if (severity === "warning" || severity === "error" || severity === "critical") {
      recentHighSeverityCount += 1;
    }

    if (type.startsWith("containment_")) {
      containmentEventCount += 1;
    }

    if (type === "admin_endpoint_unauthorized") {
      unauthorizedAdminAttempts += 1;
    }
  }

  const threatPressure = calculateThreatPressureFromCounters(counters, mode);

  return {
    ok: true,
    timestamp: new Date(timestamp).toISOString(),
    mode,
    containmentMode: safeString(containmentState?.mode || "normal", 30).toLowerCase(),
    threatPressure,
    eventWindowSize: safeInt(Array.isArray(events) ? events.length : 0, 0, 0, 1000),
    counters: {
      totalSignals: safeInt(counters.totalSignals, 0),
      criticalSignals: safeInt(counters.criticalSignals, 0),
      blockSignals: safeInt(counters.blockSignals, 0),
      challengeSignals: safeInt(counters.challengeSignals, 0),
      repeatedOffenderSignals: safeInt(counters.repeatedOffenderSignals, 0),
      lockdownTriggers: safeInt(counters.lockdownTriggers, 0),
      highRiskStateSignals: safeInt(counters.highRiskStateSignals, 0),
      routePressureSignals: safeInt(counters.routePressureSignals, 0)
    },
    eventCounts: {
      bySeverity: severityCounts,
      byAction: actionCounts
    },
    highlights: {
      recentHighSeverityCount,
      containmentEventCount,
      unauthorizedAdminAttempts,
      forceCaptchaEnabled: containmentState?.flags?.forceCaptcha === true,
      lockdownActive: containmentState?.flags?.lockdown === true,
      readOnlyMode: containmentState?.flags?.readOnlyMode === true
    }
  };
}
