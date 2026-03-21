import { redis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const ALERT_STATE_PREFIX = "security:alert-state";
const ALERT_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const ALERT_STATE_TTL_SECONDS = Math.max(1, Math.ceil(ALERT_STATE_TTL_MS / 1000));
const ALERT_SUPPRESSION_WINDOW_MS = 15 * 60 * 1000;

const ALLOWED_SEVERITIES = new Set([
  "info",
  "warning",
  "critical"
]);

function safeString(value, maxLength = 200) {
  return String(value || "")
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
  return safeString(value || "", 160).replace(/[^a-zA-Z0-9:_-]/g, "_");
}

function normalizeSeverity(value = "warning") {
  const normalized = safeString(value || "warning", 20).toLowerCase();
  return ALLOWED_SEVERITIES.has(normalized) ? normalized : "warning";
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
    lastTriggeredAt: safeInt(state.lastTriggeredAt, base.lastTriggeredAt, 0, Date.now() + 60_000),
    triggerCount: safeInt(state.triggerCount, base.triggerCount, 0, 1_000_000)
  };
}

async function getStoredAlertState(alertType) {
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
      if (!parsed || typeof parsed !== "object") {
        return createDefaultAlertState(safeAlertType);
      }
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

async function storeAlertState(state) {
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

async function shouldEmitAlert(alertType, now = Date.now()) {
  const state = await getStoredAlertState(alertType);

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
    triggerCount: safeInt(state.triggerCount, 0, 0, 1_000_000) + 1
  };

  const ok = await storeAlertState(nextState);

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
    metadata: metadata && typeof metadata === "object" ? metadata : {}
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
        ...((alert.metadata && typeof alert.metadata === "object") ? alert.metadata : {})
      }
    });
  } catch (error) {
    console.error("Security alert event write failed:", error);
  }
}

export async function evaluateSecurityAlerts({
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

  const recentCriticalEvents =
    safeInt(metrics?.eventCounts?.bySeverity?.critical, 0, 0, 1_000_000);
  const recentWarningEvents =
    safeInt(metrics?.eventCounts?.bySeverity?.warning, 0, 0, 1_000_000);
  const unauthorizedAdminAttempts =
    safeInt(metrics?.highlights?.unauthorizedAdminAttempts, 0, 0, 1_000_000);
  const containmentEventCount =
    safeInt(metrics?.highlights?.containmentEventCount, 0, 0, 1_000_000);

  const anomalyScore = safeInt(anomalyResult?.anomalyScore, 0, 0, 100);
  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);
  const finalAction = safeString(risk?.finalAction || risk?.action || "allow", 20).toLowerCase();

  if (mode === "lockdown") {
    pushAlert(alerts, buildAlert({
      type: "lockdown_active",
      severity: "critical",
      title: "Lockdown active",
      message: "System is currently operating in lockdown mode.",
      reason: "lockdown_active",
      metadata: {
        mode,
        threatPressure
      }
    }));
  }

  if (threatPressure >= 85) {
    pushAlert(alerts, buildAlert({
      type: "threat_pressure_critical",
      severity: "critical",
      title: "Threat pressure critical",
      message: "Threat pressure is critically high across the system.",
      reason: "threat_pressure_critical",
      metadata: {
        threatPressure
      }
    }));
  } else if (threatPressure >= 65) {
    pushAlert(alerts, buildAlert({
      type: "threat_pressure_elevated",
      severity: "warning",
      title: "Threat pressure elevated",
      message: "Threat pressure is elevated and should be monitored closely.",
      reason: "threat_pressure_elevated",
      metadata: {
        threatPressure
      }
    }));
  }

  if (recentCriticalEvents >= 2) {
    pushAlert(alerts, buildAlert({
      type: "critical_events_cluster",
      severity: "critical",
      title: "Cluster of critical events",
      message: "Multiple critical security events were seen in the recent event window.",
      reason: "critical_events_cluster",
      metadata: {
        recentCriticalEvents
      }
    }));
  } else if (recentWarningEvents >= 6) {
    pushAlert(alerts, buildAlert({
      type: "warning_events_cluster",
      severity: "warning",
      title: "Cluster of warning events",
      message: "Many warning-level security events were seen recently.",
      reason: "warning_events_cluster",
      metadata: {
        recentWarningEvents
      }
    }));
  }

  if (unauthorizedAdminAttempts >= 3) {
    pushAlert(alerts, buildAlert({
      type: "repeated_unauthorized_admin_access",
      severity: "critical",
      title: "Repeated unauthorized admin access",
      message: "Protected security endpoints are seeing repeated unauthorized access attempts.",
      reason: "repeated_unauthorized_admin_access",
      metadata: {
        unauthorizedAdminAttempts
      }
    }));
  }

  if (containmentEventCount >= 3) {
    pushAlert(alerts, buildAlert({
      type: "containment_activity_spike",
      severity: "warning",
      title: "Containment activity spike",
      message: "Containment-related state changes are occurring frequently.",
      reason: "containment_activity_spike",
      metadata: {
        containmentEventCount
      }
    }));
  }

  if (anomalyScore >= 70) {
    pushAlert(alerts, buildAlert({
      type: "high_anomaly_detected",
      severity: "warning",
      title: "High anomaly detected",
      message: "Behavioral anomaly detection returned a high score.",
      reason: "high_anomaly_detected",
      metadata: {
        anomalyScore
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
        finalAction
      }
    }));
  }

  const recentAlertableEvents = safeEvents.filter((event) => {
    const type = safeString(event?.type || "", 120).toLowerCase();
    return (
      type === "adaptive_mode_changed" ||
      type === "anomaly_detected" ||
      type === "containment_updated" ||
      type === "admin_endpoint_unauthorized"
    );
  });

  if (recentAlertableEvents.length >= 5) {
    pushAlert(alerts, buildAlert({
      type: "alertable_event_surge",
      severity: "warning",
      title: "Alertable event surge",
      message: "Multiple high-signal security events occurred in the recent window.",
      reason: "alertable_event_surge",
      metadata: {
        recentAlertableEvents: recentAlertableEvents.length
      }
    }));
  }

  const emittedAlerts = [];
  const now = Date.now();

  for (const alert of alerts) {
    const decision = await shouldEmitAlert(alert.type, now);

    if (!decision.shouldEmit) {
      continue;
    }

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
