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

/* -------------------- SAFETY -------------------- */

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
  return ALLOWED_SEVERITIES.has(normalized) ? normalized : "warning";
}

/* -------------------- STATE -------------------- */

function buildAlertStateKey(alertType, scopeKey = "") {
  return `${ALERT_STATE_PREFIX}:${normalizeKey(alertType)}:${normalizeKey(scopeKey || "global")}`;
}

function createDefaultAlertState(alertType = "", scopeKey = "") {
  return {
    alertType: normalizeKey(alertType),
    scopeKey: normalizeKey(scopeKey || "global"),
    lastTriggeredAt: 0,
    triggerCount: 0,
    lastSeverity: "info",
    lastReason: ""
  };
}

function normalizeAlertState(raw, alertType = "", scopeKey = "") {
  const base = createDefaultAlertState(alertType, scopeKey);
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    alertType: normalizeKey(state.alertType || base.alertType),
    scopeKey: normalizeKey(state.scopeKey || base.scopeKey),
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

async function getStoredAlertState(env, alertType, scopeKey = "") {
  const redis = getRedis(env);
  const safeAlertType = normalizeKey(alertType);
  const safeScopeKey = normalizeKey(scopeKey || "global");

  if (!safeAlertType) {
    return createDefaultAlertState(safeAlertType, safeScopeKey);
  }

  try {
    const key = buildAlertStateKey(safeAlertType, safeScopeKey);
    const raw = await redis.get(key);

    if (!raw) {
      return createDefaultAlertState(safeAlertType, safeScopeKey);
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      return normalizeAlertState(parsed, safeAlertType, safeScopeKey);
    }

    if (typeof raw === "object") {
      return normalizeAlertState(raw, safeAlertType, safeScopeKey);
    }

    return createDefaultAlertState(safeAlertType, safeScopeKey);
  } catch (error) {
    console.error("Alert state read failed:", error);
    return createDefaultAlertState(safeAlertType, safeScopeKey);
  }
}

async function storeAlertState(env, state) {
  const redis = getRedis(env);
  const normalized = normalizeAlertState(
    state,
    state?.alertType || "",
    state?.scopeKey || ""
  );

  if (!normalized.alertType) {
    return false;
  }

  try {
    const key = buildAlertStateKey(normalized.alertType, normalized.scopeKey);

    await redis.set(key, JSON.stringify(normalized), {
      ex: ALERT_STATE_TTL_SECONDS
    });

    return true;
  } catch (error) {
    console.error("Alert state write failed:", error);
    return false;
  }
}

/* -------------------- SUPPRESSION -------------------- */

function buildAlertScopeKey(alert = {}) {
  const metadata = alert?.metadata && typeof alert.metadata === "object"
    ? alert.metadata
    : {};

  return normalizeKey(
    metadata.actorKey ||
      metadata.userId ||
      metadata.route ||
      metadata.reasonKey ||
      "global"
  );
}

async function shouldEmitAlert(env, alertType, severity = "warning", reason = "", scopeKey = "", now = Date.now()) {
  const state = await getStoredAlertState(env, alertType, scopeKey);
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
    scopeKey: normalizeKey(scopeKey || "global"),
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

/* -------------------- ALERT BUILDING -------------------- */

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
  category = "security",
  priority = "medium",
  escalationRequired = false,
  metadata = {}
}) {
  return {
    type: normalizeKey(type),
    severity: normalizeSeverity(severity),
    title: safeString(title, 120),
    message: safeString(message, 300),
    reason: safeString(reason, 120),
    category: safeString(category, 50).toLowerCase(),
    priority: safeString(priority, 30).toLowerCase(),
    escalationRequired: escalationRequired === true,
    metadata: metadata && typeof metadata === "object"
      ? metadata
      : {}
  };
}

function deriveAlertEventAction(alert) {
  const type = safeString(alert?.type || "", 120).toLowerCase();
  const severity = normalizeSeverity(alert?.severity || "warning");

  if (
    type.includes("lockdown") ||
    type.includes("critical_attack") ||
    type.includes("breach") ||
    type.includes("exploit") ||
    type.includes("session_kill") ||
    type.includes("account_lock") ||
    type.includes("actor_block")
  ) {
    return "contain";
  }

  if (severity === "critical") {
    return "contain";
  }

  return "observe";
}

async function emitAlertEvent(env, alert) {
  try {
    await appendSecurityEvent(env, {
      type: "security_alert_triggered",
      severity: normalizeSeverity(alert.severity),
      action: deriveAlertEventAction(alert),
      reason: safeString(alert.reason || alert.type || "security_alert", 120),
      message: safeString(alert.message || "Security alert triggered.", 500),
      metadata: {
        alertType: safeString(alert.type || "", 120),
        alertTitle: safeString(alert.title || "", 120),
        category: safeString(alert.category || "security", 50),
        priority: safeString(alert.priority || "medium", 30),
        escalationRequired: alert.escalationRequired === true,
        ...(alert.metadata || {})
      }
    });
  } catch (error) {
    console.error("Security alert event write failed:", error);
  }
}

/* -------------------- NORMALIZATION -------------------- */

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

/* -------------------- MAIN -------------------- */

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

  const containmentFlags =
    containment?.flags && typeof containment.flags === "object"
      ? containment.flags
      : {};

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
    (event) => safeString(event?.severity || "", 20).toLowerCase() === "critical"
  ).length;

  /* --- ALERT CONDITIONS --- */

  if (mode === "lockdown") {
    pushAlert(alerts, buildAlert({
      type: "lockdown_active",
      severity: "critical",
      title: "Lockdown active",
      message: "System is currently operating in lockdown mode.",
      reason: "lockdown_active",
      category: "containment",
      priority: "critical",
      escalationRequired: true,
      metadata: { mode, threatPressure, reasonKey: "lockdown_active" }
    }));
  }

  if (threatPressure >= 85) {
    pushAlert(alerts, buildAlert({
      type: "threat_pressure_critical",
      severity: "critical",
      title: "Threat pressure critical",
      message: "Threat pressure is critically high across the system.",
      reason: "threat_pressure_critical",
      category: "threat",
      priority: "critical",
      escalationRequired: true,
      metadata: { threatPressure, reasonKey: "threat_pressure_critical" }
    }));
  }

  if (anomalyScore >= 70) {
    pushAlert(alerts, buildAlert({
      type: "high_anomaly_detected",
      severity: normalizedAnomaly.breachSignals > 0 ? "critical" : "warning",
      title: "High anomaly detected",
      message: "Behavioral anomaly detection returned a high score.",
      reason: "high_anomaly_detected",
      category: "anomaly",
      priority: normalizedAnomaly.breachSignals > 0 ? "critical" : "high",
      escalationRequired: normalizedAnomaly.breachSignals > 0,
      metadata: {
        anomalyScore,
        exploitSignals: normalizedAnomaly.exploitSignals,
        breachSignals: normalizedAnomaly.breachSignals,
        coordinatedSignals: normalizedAnomaly.coordinatedSignals,
        replaySignals: normalizedAnomaly.replaySignals,
        reasonKey: "high_anomaly_detected"
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
      category: "risk",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        riskScore,
        finalAction,
        hardBlockSignals: normalizedRisk.hardBlockSignals,
        criticalSignals: normalizedRisk.criticalSignals,
        reasonKey: "critical_actor_risk"
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
      category: "attack",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        riskScore,
        anomalyScore,
        reasonKey: "critical_attack_likely"
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
      category: "attack",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        exploitSignals: normalizedAnomaly.exploitSignals,
        anomalyScore,
        reasonKey: "exploit_signal_detected"
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
      category: "attack",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        breachSignals: normalizedAnomaly.breachSignals,
        anomalyScore,
        reasonKey: "breach_signal_detected"
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
      category: "attack",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        coordinatedSignals: normalizedAnomaly.coordinatedSignals,
        anomalyScore,
        reasonKey: "coordinated_attack_detected"
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
      category: "attack",
      priority: "high",
      escalationRequired: false,
      metadata: {
        replaySignals: normalizedAnomaly.replaySignals,
        reasonKey: "replay_attack_signal"
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
      category: "events",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        recentCriticalEvents,
        reasonKey: "critical_event_cluster"
      }
    }));
  }

  if (containmentFlags.lockAccount === true) {
    pushAlert(alerts, buildAlert({
      type: "account_lock_enforced",
      severity: "critical",
      title: "Account lock enforced",
      message: "Containment state indicates an account lock is active.",
      reason: "account_lock_enforced",
      category: "containment",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        reasonKey: "account_lock_enforced"
      }
    }));
  }

  if (containmentFlags.killSessions === true) {
    pushAlert(alerts, buildAlert({
      type: "session_kill_enforced",
      severity: "critical",
      title: "Session kill enforced",
      message: "Containment state indicates active sessions should be invalidated.",
      reason: "session_kill_enforced",
      category: "containment",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        reasonKey: "session_kill_enforced"
      }
    }));
  }

  if (containmentFlags.blockActor === true) {
    pushAlert(alerts, buildAlert({
      type: "actor_block_enforced",
      severity: "critical",
      title: "Actor block enforced",
      message: "Containment state indicates a targeted actor block is active.",
      reason: "actor_block_enforced",
      category: "containment",
      priority: "critical",
      escalationRequired: true,
      metadata: {
        reasonKey: "actor_block_enforced"
      }
    }));
  }

  const emittedAlerts = [];
  const now = Date.now();

  for (const alert of alerts) {
    const scopeKey = buildAlertScopeKey(alert);

    const decision = await shouldEmitAlert(
      env,
      alert.type,
      alert.severity,
      alert.reason,
      scopeKey,
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
