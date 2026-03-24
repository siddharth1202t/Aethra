import { getRedis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const ALERT_STATE_PREFIX = "security:alert-state";
const ALERT_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const ALERT_SUPPRESSION_WINDOW_MS = 15 * 60 * 1000;

const ALERT_STATE_TTL_SECONDS = Math.max(
  1,
  Math.ceil(ALERT_STATE_TTL_MS / 1000)
);

const ALLOWED_SEVERITIES = new Set([
  "info",
  "warning",
  "critical"
]);

function safeString(value, maxLength = 200) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeInt(value, fallback = 0, min = 0, max = 1_000_000) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function normalizeKey(value = "") {
  return safeString(value, 160).replace(/[^a-zA-Z0-9:_-]/g, "_");
}

function normalizeSeverity(value = "warning") {
  const normalized = safeString(value, 20).toLowerCase();
  return ALLOWED_SEVERITIES.has(normalized)
    ? normalized
    : "warning";
}

function buildAlertStateKey(alertType) {
  return `${ALERT_STATE_PREFIX}:${normalizeKey(alertType)}`;
}

function createDefaultAlertState(alertType = "") {
  return {
    alertType: normalizeKey(alertType),
    lastTriggeredAt: 0,
    triggerCount: 0,
    lastSeverity: "info",
    lastReason: ""
  };
}

function normalizeAlertState(raw, alertType = "") {
  const base = createDefaultAlertState(alertType);
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    alertType: normalizeKey(state.alertType || base.alertType),
    lastTriggeredAt: safeInt(
      state.lastTriggeredAt,
      base.lastTriggeredAt,
      0,
      Date.now() + 60_000
    ),
    triggerCount: safeInt(
      state.triggerCount,
      base.triggerCount,
      0,
      1_000_000
    ),
    lastSeverity: normalizeSeverity(state.lastSeverity || base.lastSeverity),
    lastReason: safeString(state.lastReason || base.lastReason, 120)
  };
}

async function getStoredAlertState(env, alertType) {
  const redis = getRedis(env);
  const safeAlertType = normalizeKey(alertType);

  if (!safeAlertType) {
    return createDefaultAlertState(safeAlertType);
  }

  try {
    const key = buildAlertStateKey(safeAlertType);
    const raw = await redis.get(key);

    if (!raw) {
      return createDefaultAlertState(safeAlertType);
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      return normalizeAlertState(parsed, safeAlertType);
    }

    if (typeof raw === "object") {
      return normalizeAlertState(raw, safeAlertType);
    }

    return createDefaultAlertState(safeAlertType);
  } catch (error) {
    console.error("Alert state read failed:", error);
    return createDefaultAlertState(safeAlertType);
  }
}

async function storeAlertState(env, state) {
  const redis = getRedis(env);
  const normalized = normalizeAlertState(state, state?.alertType || "");

  if (!normalized.alertType) {
    return false;
  }

  try {
    const key = buildAlertStateKey(normalized.alertType);

    await redis.set(key, JSON.stringify(normalized), {
      ex: ALERT_STATE_TTL_SECONDS
    });

    return true;
  } catch (error) {
    console.error("Alert state write failed:", error);
    return false;
  }
}

async function shouldEmitAlert(env, alertType, severity = "warning", reason = "", now = Date.now()) {
  const state = await getStoredAlertState(env, alertType);
  const normalizedSeverity = normalizeSeverity(severity);
  const normalizedReason = safeString(reason || "", 120);

  const severityChanged = state.lastSeverity !== normalizedSeverity;
  const reasonChanged = state.lastReason !== normalizedReason;

  if (
    state.lastTriggeredAt > 0 &&
    now - state.lastTriggeredAt < ALERT_SUPPRESSION_WINDOW_MS &&
    !severityChanged &&
    !reasonChanged
  ) {
    return {
      shouldEmit: false,
      state
    };
  }

  const nextState = {
    alertType: normalizeKey(alertType),
    lastTriggeredAt: now,
    triggerCount: safeInt(state.triggerCount, 0) + 1,
    lastSeverity: normalizedSeverity,
    lastReason: normalizedReason
  };

  const ok = await storeAlertState(env, nextState);

  return {
    shouldEmit: ok,
    state: nextState
  };
}

function pushAlert(alerts, alert) {
  if (!alert || typeof alert !== "object") return;
  alerts.push(alert);
}

function buildAlert({
  type,
  severity,
  title,
  message,
  reason,
  metadata = {}
}) {
  return {
    type: normalizeKey(type),
    severity: normalizeSeverity(severity),
    title: safeString(title, 120),
    message: safeString(message, 300),
    reason: safeString(reason, 120),
    metadata: metadata && typeof metadata === "object"
      ? metadata
      : {}
  };
}

async function emitAlertEvent(env, alert) {
  try {
    await appendSecurityEvent(env, {
      type: "security_alert_triggered",
      severity: normalizeSeverity(alert.severity),
      action: alert.severity === "critical" ? "contain" : "observe",
      reason: safeString(alert.reason || alert.type || "security_alert", 120),
      message: safeString(alert.message || "Security alert triggered.", 500),
      metadata: {
        alertType: safeString(alert.type || "", 120),
        alertTitle: safeString(alert.title || "", 120),
        ...(alert.metadata || {})
      }
    });
  } catch (error) {
    console.error("Security alert event write failed:", error);
  }
}

function normalizeRisk(risk = null) {
  if (!risk || typeof risk !== "object") return {};

  return {
    riskScore: safeInt(risk.riskScore, 0, 0, 100),
    level: safeString(risk.level || "low", 20).toLowerCase(),
    finalAction: safeString(risk.finalAction || risk.action || "allow", 20).toLowerCase(),
    hardBlockSignals: safeInt(risk.hardBlockSignals, 0, 0, 100),
    criticalSignals: safeInt(risk.criticalSignals, 0, 0, 100),
    criticalAttackLikely: risk.criticalAttackLikely === true
  };
}

function normalizeAnomalyResult(anomalyResult = null) {
  if (!anomalyResult || typeof anomalyResult !== "object") return {};

  return {
    anomalyScore: safeInt(anomalyResult.anomalyScore, 0, 0, 100),
    level: safeString(anomalyResult.level || "low", 20).toLowerCase(),
    exploitSignals: safeInt(anomalyResult?.events?.exploitSignals, 0, 0, 100),
    breachSignals: safeInt(anomalyResult?.events?.breachSignals, 0, 0, 100),
    coordinatedSignals: safeInt(anomalyResult?.events?.coordinatedSignals, 0, 0, 100),
    replaySignals: safeInt(anomalyResult?.events?.replaySignals, 0, 0, 100)
  };
}

export async function evaluateSecurityAlerts({
  env = {},
  securityStatus = null,
  securityMetrics = null,
  events = [],
  anomalyResult = null,
  risk = null,
  adaptiveMode = null,
  containment = null
} = {}) {
  const alerts = [];

  const metrics = securityMetrics && typeof securityMetrics === "object"
    ? securityMetrics
    : {};

  const status = securityStatus && typeof securityStatus === "object"
    ? securityStatus
    : {};

  const safeEvents = Array.isArray(events) ? events : [];
  const normalizedRisk = normalizeRisk(risk);
  const normalizedAnomaly = normalizeAnomalyResult(anomalyResult);

  const mode = safeString(
    containment?.mode ||
    adaptiveMode?.mode ||
    status.mode ||
    metrics.mode ||
    "normal",
    30
  ).toLowerCase();

  const threatPressure = safeInt(
    status.threatPressure ?? metrics.threatPressure ?? 0,
    0,
    0,
    100
  );

  const anomalyScore = safeInt(normalizedAnomaly.anomalyScore, 0, 0, 100);
  const riskScore = safeInt(normalizedRisk.riskScore, 0, 0, 100);
  const finalAction = safeString(normalizedRisk.finalAction || "allow", 20).toLowerCase();

  const recentCriticalEvents = safeEvents.filter(
    (event) =>
      safeString(event?.severity || "", 20).toLowerCase() === "critical"
  ).length;

  /* --- ALERT CONDITIONS --- */

  if (mode === "lockdown") {
    pushAlert(alerts, buildAlert({
      type: "lockdown_active",
      severity: "critical",
      title: "Lockdown active",
      message: "System is currently operating in lockdown mode.",
      reason: "lockdown_active",
      metadata: { mode, threatPressure }
    }));
  }

  if (threatPressure >= 85) {
    pushAlert(alerts, buildAlert({
      type: "threat_pressure_critical",
      severity: "critical",
      title: "Threat pressure critical",
      message: "Threat pressure is critically high across the system.",
      reason: "threat_pressure_critical",
      metadata: { threatPressure }
    }));
  }

  if (anomalyScore >= 70) {
    pushAlert(alerts, buildAlert({
      type: "high_anomaly_detected",
      severity: normalizedAnomaly.breachSignals > 0 ? "critical" : "warning",
      title: "High anomaly detected",
      message: "Behavioral anomaly detection returned a high score.",
      reason: "high_anomaly_detected",
      metadata: {
        anomalyScore,
        exploitSignals: normalizedAnomaly.exploitSignals,
        breachSignals: normalizedAnomaly.breachSignals,
        coordinatedSignals: normalizedAnomaly.coordinatedSignals,
        replaySignals: normalizedAnomaly.replaySignals
      }
    }));
  }

  if (riskScore >= 90 || finalAction === "block") {
    pushAlert(alerts, buildAlert({
      type: "critical_actor_risk",
      severity: "critical",
      title: "Critical actor risk",
      message: "An actor reached critical risk or triggered a block decision.",
      reason: "critical_actor_risk",
      metadata: {
        riskScore,
        finalAction,
        hardBlockSignals: normalizedRisk.hardBlockSignals,
        criticalSignals: normalizedRisk.criticalSignals
      }
    }));
  }

  if (normalizedRisk.criticalAttackLikely === true) {
    pushAlert(alerts, buildAlert({
      type: "critical_attack_likely",
      severity: "critical",
      title: "Critical attack likely",
      message: "Signals indicate a likely critical attack or exploitation attempt.",
      reason: "critical_attack_likely",
      metadata: {
        riskScore,
        anomalyScore
      }
    }));
  }

  if (normalizedAnomaly.exploitSignals > 0) {
    pushAlert(alerts, buildAlert({
      type: "exploit_signal_detected",
      severity: "critical",
      title: "Exploit signal detected",
      message: "Exploit-like behavior was detected by anomaly analysis.",
      reason: "exploit_signal_detected",
      metadata: {
        exploitSignals: normalizedAnomaly.exploitSignals,
        anomalyScore
      }
    }));
  }

  if (normalizedAnomaly.breachSignals > 0) {
    pushAlert(alerts, buildAlert({
      type: "breach_signal_detected",
      severity: "critical",
      title: "Breach signal detected",
      message: "Potential breach-like behavior was detected.",
      reason: "breach_signal_detected",
      metadata: {
        breachSignals: normalizedAnomaly.breachSignals,
        anomalyScore
      }
    }));
  }

  if (normalizedAnomaly.coordinatedSignals > 0) {
    pushAlert(alerts, buildAlert({
      type: "coordinated_attack_detected",
      severity: "critical",
      title: "Coordinated attack detected",
      message: "Coordinated multi-signal attack behavior was detected.",
      reason: "coordinated_attack_detected",
      metadata: {
        coordinatedSignals: normalizedAnomaly.coordinatedSignals,
        anomalyScore
      }
    }));
  }

  if (normalizedAnomaly.replaySignals > 0) {
    pushAlert(alerts, buildAlert({
      type: "replay_attack_signal",
      severity: "warning",
      title: "Replay attack signal",
      message: "Replay-like request behavior was detected.",
      reason: "replay_attack_signal",
      metadata: {
        replaySignals: normalizedAnomaly.replaySignals
      }
    }));
  }

  if (recentCriticalEvents >= 3) {
    pushAlert(alerts, buildAlert({
      type: "critical_event_cluster",
      severity: "critical",
      title: "Critical event cluster",
      message: "Multiple critical security events were observed recently.",
      reason: "critical_event_cluster",
      metadata: {
        recentCriticalEvents
      }
    }));
  }

  const emittedAlerts = [];
  const now = Date.now();

  for (const alert of alerts) {
    const decision = await shouldEmitAlert(
      env,
      alert.type,
      alert.severity,
      alert.reason,
      now
    );

    if (!decision.shouldEmit) continue;

    await emitAlertEvent(env, alert);
    emittedAlerts.push(alert);
  }

  return {
    ok: true,
    totalEvaluated: alerts.length,
    totalEmitted: emittedAlerts.length,
    alerts: emittedAlerts
  };
}
