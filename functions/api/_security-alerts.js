<<<<<<< HEAD
import { redis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";
=======
import { getRedis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";
>>>>>>> 462287806a8da117fc6781c19b96bf5570233eaa

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
    triggerCount: 0
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
    )
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

async function shouldEmitAlert(env, alertType, now = Date.now()) {
  const state = await getStoredAlertState(env, alertType);

  if (
    state.lastTriggeredAt > 0 &&
    now - state.lastTriggeredAt < ALERT_SUPPRESSION_WINDOW_MS
  ) {
    return {
      shouldEmit: false,
      state
    };
  }

  const nextState = {
    alertType: normalizeKey(alertType),
    lastTriggeredAt: now,
    triggerCount: safeInt(state.triggerCount, 0) + 1
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

async function emitAlertEvent(alert) {
  try {
    await appendSecurityEvent({
      type: "security_alert_triggered",
      severity: normalizeSeverity(alert.severity),
      action: "observe",
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

export async function evaluateSecurityAlerts({
  env = {},
  securityStatus = null,
  securityMetrics = null,
  events = [],
  anomalyResult = null,
  risk = null
} = {}) {

  const alerts = [];

  const metrics = securityMetrics && typeof securityMetrics === "object"
    ? securityMetrics
    : {};

  const status = securityStatus && typeof securityStatus === "object"
    ? securityStatus
    : {};

  const safeEvents = Array.isArray(events) ? events : [];

  const mode = safeString(status.mode || metrics.mode || "normal", 30).toLowerCase();

  const threatPressure = safeInt(
    status.threatPressure ?? metrics.threatPressure ?? 0,
    0,
    0,
    100
  );

  const anomalyScore = safeInt(anomalyResult?.anomalyScore, 0, 0, 100);
  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);

  const finalAction = safeString(
    risk?.finalAction || risk?.action || "allow",
    20
  ).toLowerCase();

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
      severity: "warning",
      title: "High anomaly detected",
      message: "Behavioral anomaly detection returned a high score.",
      reason: "high_anomaly_detected",
      metadata: { anomalyScore }
    }));
  }

  if (riskScore >= 90 || finalAction === "block") {
    pushAlert(alerts, buildAlert({
      type: "critical_actor_risk",
      severity: "critical",
      title: "Critical actor risk",
      message: "An actor reached critical risk or triggered a block decision.",
      reason: "critical_actor_risk",
      metadata: { riskScore, finalAction }
    }));
  }

  const emittedAlerts = [];
  const now = Date.now();

  for (const alert of alerts) {
    const decision = await shouldEmitAlert(env, alert.type, now);

    if (!decision.shouldEmit) continue;

    await emitAlertEvent(alert);
    emittedAlerts.push(alert);
  }

  return {
    ok: true,
    totalEvaluated: alerts.length,
    totalEmitted: emittedAlerts.length,
    alerts: emittedAlerts
  };
}
