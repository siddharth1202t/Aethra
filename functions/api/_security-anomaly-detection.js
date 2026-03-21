import { redis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-events-store.js";

const ANOMALY_STATE_PREFIX = "security:anomaly-state";
const ANOMALY_STATE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const ANOMALY_STATE_TTL_SECONDS = Math.max(1, Math.ceil(ANOMALY_STATE_TTL_MS / 1000));
const MAX_COUNTER_VALUE = 1_000_000;
const MAX_REASON_LENGTH = 120;
const MAX_REASONS = 20;
const MAX_RECENT_ITEMS = 10;

const ALLOWED_LEVELS = new Set([
  "low",
  "medium",
  "high",
  "critical"
]);

const ALLOWED_ACTIONS = new Set([
  "allow",
  "throttle",
  "challenge",
  "block"
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

function safeInt(value, fallback = 0, min = 0, max = MAX_COUNTER_VALUE) {
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

function normalizeLevel(value = "low") {
  const normalized = safeString(value || "low", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "low";
}

function normalizeAction(value = "allow") {
  const normalized = safeString(value || "allow", 20).toLowerCase();
  return ALLOWED_ACTIONS.has(normalized) ? normalized : "allow";
}

function normalizeKey(value = "") {
  return safeString(value || "", 160).replace(/[^a-zA-Z0-9:_-]/g, "_");
}

function normalizeRoute(value = "") {
  const raw = safeString(value || "", 300);

  if (!raw) return "";

  return raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_-]/g, "")
    .toLowerCase()
    .slice(0, 200);
}

function normalizeIp(value = "") {
  return safeString(value || "", 100);
}

function normalizeUserId(value = "") {
  return safeString(value || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function normalizeSessionId(value = "") {
  return safeString(value || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function normalizeReason(reason = "") {
  return safeString(reason || "", MAX_REASON_LENGTH).replace(/[^\w:.-]/g, "_");
}

function pushReason(reasons, reason) {
  const safeReason = normalizeReason(reason);
  if (!safeReason) return;

  if (!reasons.includes(safeReason)) {
    reasons.push(safeReason);
  }
}

function buildStateKey(actorType, actorId) {
  return `${ANOMALY_STATE_PREFIX}:${normalizeKey(actorType)}:${normalizeKey(actorId)}`;
}

function createDefaultState(actorType = "session", actorId = "") {
  const now = Date.now();

  return {
    actorType: normalizeKey(actorType),
    actorId: normalizeKey(actorId),
    updatedAt: now,
    createdAt: now,
    recentIps: [],
    recentRoutes: [],
    recentActions: [],
    recentRiskScores: [],
    loginCount: 0,
    signupCount: 0,
    passwordResetCount: 0,
    writeActionCount: 0,
    suspiciousBurstCount: 0,
    ipChangeCount: 0,
    routeSpreadCount: 0
  };
}

function normalizeStringArray(values = [], maxItems = MAX_RECENT_ITEMS, maxLength = 120) {
  if (!Array.isArray(values)) return [];

  const output = [];

  for (const value of values) {
    const normalized = safeString(value, maxLength);
    if (!normalized) continue;
    if (!output.includes(normalized)) {
      output.push(normalized);
    }
    if (output.length >= maxItems) break;
  }

  return output;
}

function normalizeNumberArray(values = [], maxItems = MAX_RECENT_ITEMS) {
  if (!Array.isArray(values)) return [];

  const output = [];

  for (const value of values) {
    output.push(safeInt(value, 0, 0, 100));
    if (output.length >= maxItems) break;
  }

  return output;
}

function normalizeState(raw, actorType = "session", actorId = "") {
  const base = createDefaultState(actorType, actorId);
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    actorType: normalizeKey(state.actorType || base.actorType),
    actorId: normalizeKey(state.actorId || base.actorId),
    updatedAt: safeInt(state.updatedAt, base.updatedAt, 0, Date.now() + 60_000),
    createdAt: safeInt(state.createdAt, base.createdAt, 0, Date.now() + 60_000),
    recentIps: normalizeStringArray(state.recentIps, MAX_RECENT_ITEMS, 100),
    recentRoutes: normalizeStringArray(state.recentRoutes, MAX_RECENT_ITEMS, 200),
    recentActions: normalizeStringArray(state.recentActions, MAX_RECENT_ITEMS, 40),
    recentRiskScores: normalizeNumberArray(state.recentRiskScores, MAX_RECENT_ITEMS),
    loginCount: safeInt(state.loginCount, 0),
    signupCount: safeInt(state.signupCount, 0),
    passwordResetCount: safeInt(state.passwordResetCount, 0),
    writeActionCount: safeInt(state.writeActionCount, 0),
    suspiciousBurstCount: safeInt(state.suspiciousBurstCount, 0),
    ipChangeCount: safeInt(state.ipChangeCount, 0),
    routeSpreadCount: safeInt(state.routeSpreadCount, 0)
  };
}

function getLevel(score) {
  const safeScore = safeInt(score, 0, 0, 100);

  if (safeScore >= 90) return "critical";
  if (safeScore >= 70) return "high";
  if (safeScore >= 40) return "medium";
  return "low";
}

function getAction(score) {
  const safeScore = safeInt(score, 0, 0, 100);

  if (safeScore >= 90) return "block";
  if (safeScore >= 70) return "challenge";
  if (safeScore >= 40) return "throttle";
  return "allow";
}

async function getStoredState(actorType, actorId) {
  const safeActorType = normalizeKey(actorType);
  const safeActorId = normalizeKey(actorId);

  if (!safeActorId) {
    return createDefaultState(safeActorType, safeActorId);
  }

  try {
    const key = buildStateKey(safeActorType, safeActorId);
    const raw = await redis.get(key);

    if (!raw) {
      return createDefaultState(safeActorType, safeActorId);
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      if (!parsed || typeof parsed !== "object") {
        return createDefaultState(safeActorType, safeActorId);
      }
      return normalizeState(parsed, safeActorType, safeActorId);
    }

    if (typeof raw === "object") {
      return normalizeState(raw, safeActorType, safeActorId);
    }

    return createDefaultState(safeActorType, safeActorId);
  } catch (error) {
    console.error("Anomaly state read failed:", error);
    return createDefaultState(safeActorType, safeActorId);
  }
}

async function storeState(state) {
  const normalized = normalizeState(
    state,
    state?.actorType || "session",
    state?.actorId || ""
  );

  if (!normalized.actorId) {
    return false;
  }

  try {
    const key = buildStateKey(normalized.actorType, normalized.actorId);
    await redis.set(key, JSON.stringify(normalized), {
      ex: ANOMALY_STATE_TTL_SECONDS
    });
    return true;
  } catch (error) {
    console.error("Anomaly state write failed:", error);
    return false;
  }
}

function pushRecentUnique(list = [], value = "", maxItems = MAX_RECENT_ITEMS) {
  const safeValue = safeString(value, 200);
  if (!safeValue) return normalizeStringArray(list, maxItems, 200);

  const next = [safeValue, ...list.filter((item) => item !== safeValue)];
  return next.slice(0, maxItems);
}

function pushRecentNumber(list = [], value = 0, maxItems = MAX_RECENT_ITEMS) {
  const safeValue = safeInt(value, 0, 0, 100);
  return [safeValue, ...list].slice(0, maxItems);
}

function buildAnomalyScore({
  previousState,
  nextState,
  currentIp = "",
  currentRoute = "",
  riskScore = 0,
  isWriteAction = false,
  actionType = ""
}) {
  let score = 0;
  const reasons = [];

  const safeRiskScore = safeInt(riskScore, 0, 0, 100);
  const safeRoute = normalizeRoute(currentRoute);
  const safeIp = normalizeIp(currentIp);
  const safeActionType = safeString(actionType || "", 40).toLowerCase();

  if (safeRiskScore >= 80) {
    score += 25;
    pushReason(reasons, "anomaly:high_risk_alignment");
  } else if (safeRiskScore >= 50) {
    score += 12;
    pushReason(reasons, "anomaly:medium_risk_alignment");
  }

  if (safeIp && previousState.recentIps.length > 0 && !previousState.recentIps.includes(safeIp)) {
    score += 20;
    pushReason(reasons, "anomaly:ip_change_detected");
  }

  if (nextState.ipChangeCount >= 3) {
    score += 15;
    pushReason(reasons, "anomaly:repeated_ip_changes");
  }

  if (safeRoute && !previousState.recentRoutes.includes(safeRoute) && previousState.recentRoutes.length >= 4) {
    score += 10;
    pushReason(reasons, "anomaly:new_route_after_wide_spread");
  }

  if (nextState.routeSpreadCount >= 6) {
    score += 15;
    pushReason(reasons, "anomaly:wide_route_spread");
  }

  if (nextState.suspiciousBurstCount >= 3) {
    score += 20;
    pushReason(reasons, "anomaly:suspicious_burst_pattern");
  }

  if (isWriteAction) {
    score += 8;
    pushReason(reasons, "anomaly:write_action_pressure");
  }

  if (safeActionType === "login" && nextState.loginCount >= 5) {
    score += 15;
    pushReason(reasons, "anomaly:login_spike");
  }

  if (safeActionType === "signup" && nextState.signupCount >= 3) {
    score += 15;
    pushReason(reasons, "anomaly:signup_spike");
  }

  if (
    (safeActionType === "password_reset" || safeActionType === "reset") &&
    nextState.passwordResetCount >= 3
  ) {
    score += 18;
    pushReason(reasons, "anomaly:password_reset_spike");
  }

  if (nextState.writeActionCount >= 6) {
    score += 15;
    pushReason(reasons, "anomaly:heavy_write_activity");
  }

  const recentHighRiskCount = nextState.recentRiskScores.filter((item) => item >= 60).length;
  if (recentHighRiskCount >= 3) {
    score += 20;
    pushReason(reasons, "anomaly:clustered_high_risk_scores");
  }

  return {
    anomalyScore: Math.min(100, Math.max(0, score)),
    level: getLevel(score),
    action: getAction(score),
    reasons: reasons.slice(0, MAX_REASONS)
  };
}

async function recordAnomalyEvent({
  actorType,
  actorId,
  anomalyResult,
  route = "",
  ip = ""
}) {
  try {
    await appendSecurityEvent({
      type: "anomaly_detected",
      severity:
        anomalyResult.level === "critical"
          ? "critical"
          : anomalyResult.level === "high"
            ? "warning"
            : "info",
      action:
        anomalyResult.action === "block" ||
        anomalyResult.action === "challenge" ||
        anomalyResult.action === "throttle"
          ? anomalyResult.action
          : "observe",
      route: normalizeRoute(route),
      ip: normalizeIp(ip),
      reason: anomalyResult.reasons[0] || "anomaly_detected",
      message: "Behavioral anomaly detected for actor.",
      metadata: {
        actorType: normalizeKey(actorType),
        actorId: normalizeKey(actorId),
        anomalyScore: safeInt(anomalyResult.anomalyScore, 0, 0, 100),
        anomalyLevel: normalizeLevel(anomalyResult.level),
        anomalyAction: normalizeAction(anomalyResult.action)
      }
    });
  } catch (error) {
    console.error("Anomaly event write failed:", error);
  }
}

export async function evaluateAnomalyDetection({
  actorType = "session",
  actorId = "",
  ip = "",
  route = "",
  riskScore = 0,
  isWriteAction = false,
  actionType = ""
} = {}) {
  const safeActorType = normalizeKey(actorType);
  const safeActorId = normalizeKey(actorId);

  if (!safeActorId) {
    return {
      anomalyScore: 0,
      level: "low",
      action: "allow",
      reasons: []
    };
  }

  const currentIp = normalizeIp(ip);
  const currentRoute = normalizeRoute(route);
  const now = Date.now();

  const previousState = await getStoredState(safeActorType, safeActorId);

  const nextState = normalizeState(
    {
      ...previousState,
      updatedAt: now,
      recentIps: currentIp
        ? pushRecentUnique(previousState.recentIps, currentIp, MAX_RECENT_ITEMS)
        : previousState.recentIps,
      recentRoutes: currentRoute
        ? pushRecentUnique(previousState.recentRoutes, currentRoute, MAX_RECENT_ITEMS)
        : previousState.recentRoutes,
      recentActions: actionType
        ? pushRecentUnique(previousState.recentActions, safeString(actionType, 40).toLowerCase(), MAX_RECENT_ITEMS)
        : previousState.recentActions,
      recentRiskScores: pushRecentNumber(previousState.recentRiskScores, riskScore, MAX_RECENT_ITEMS),
      loginCount:
        previousState.loginCount +
        (safeString(actionType, 40).toLowerCase() === "login" ? 1 : 0),
      signupCount:
        previousState.signupCount +
        (safeString(actionType, 40).toLowerCase() === "signup" ? 1 : 0),
      passwordResetCount:
        previousState.passwordResetCount +
        (
          safeString(actionType, 40).toLowerCase() === "password_reset" ||
          safeString(actionType, 40).toLowerCase() === "reset"
            ? 1
            : 0
        ),
      writeActionCount:
        previousState.writeActionCount + (isWriteAction ? 1 : 0),
      suspiciousBurstCount:
        previousState.suspiciousBurstCount + (safeInt(riskScore, 0, 0, 100) >= 60 ? 1 : 0),
      ipChangeCount:
        currentIp &&
        previousState.recentIps.length > 0 &&
        !previousState.recentIps.includes(currentIp)
          ? previousState.ipChangeCount + 1
          : previousState.ipChangeCount,
      routeSpreadCount:
        currentRoute &&
        !previousState.recentRoutes.includes(currentRoute)
          ? previousState.routeSpreadCount + 1
          : previousState.routeSpreadCount
    },
    safeActorType,
    safeActorId
  );

  const anomalyResult = buildAnomalyScore({
    previousState,
    nextState,
    currentIp,
    currentRoute,
    riskScore,
    isWriteAction,
    actionType
  });

  const ok = await storeState(nextState);

  if (ok && anomalyResult.anomalyScore >= 40) {
    await recordAnomalyEvent({
      actorType: safeActorType,
      actorId: safeActorId,
      anomalyResult,
      route: currentRoute,
      ip: currentIp
    });
  }

  return anomalyResult;
}
