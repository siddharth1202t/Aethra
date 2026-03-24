import { getRedis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const ANOMALY_STATE_PREFIX = "security:anomaly-state";

const ANOMALY_STATE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const ANOMALY_STATE_TTL_SECONDS = Math.max(
  1,
  Math.ceil(ANOMALY_STATE_TTL_MS / 1000)
);

const ANOMALY_DECAY_WINDOW_MS = 6 * 60 * 60 * 1000;

const MAX_COUNTER_VALUE = 1_000_000;
const MAX_REASON_LENGTH = 120;
const MAX_REASONS = 20;
const MAX_RECENT_ITEMS = 10;

const ALLOWED_LEVELS = new Set(["low", "medium", "high", "critical"]);
const ALLOWED_ACTIONS = new Set(["allow", "throttle", "challenge", "block"]);

/* ------------------------------------------------ */
/* SAFETY HELPERS */
/* ------------------------------------------------ */

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

/* ------------------------------------------------ */
/* NORMALIZATION */
/* ------------------------------------------------ */

function normalizeLevel(value = "low") {
  const v = safeString(value, 20).toLowerCase();
  return ALLOWED_LEVELS.has(v) ? v : "low";
}

function normalizeAction(value = "allow") {
  const v = safeString(value, 20).toLowerCase();
  return ALLOWED_ACTIONS.has(v) ? v : "allow";
}

function normalizeKey(value = "") {
  return safeString(value, 160).replace(/[^a-zA-Z0-9:_-]/g, "_");
}

function normalizeRoute(value = "") {
  const raw = safeString(value, 300);
  if (!raw) return "";

  return raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, 200);
}

function normalizeIp(value = "") {
  let ip = safeString(value || "", 100);

  if (!ip) return "";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return ip;
}

function normalizeReason(reason = "") {
  return safeString(reason, MAX_REASON_LENGTH).replace(/[^\w:.-]/g, "_");
}

function normalizeRouteSensitivity(value = "normal") {
  const v = safeString(value, 20).toLowerCase();
  return v === "critical" || v === "high" ? v : "normal";
}

function normalizeActionType(value = "") {
  return safeString(value || "", 50).toLowerCase().replace(/[^a-z0-9_:-]/g, "_");
}

/* ------------------------------------------------ */
/* STATE */
/* ------------------------------------------------ */

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
    routeSpreadCount: 0,
    exploitSignalCount: 0,
    breachSignalCount: 0,
    replaySignalCount: 0,
    coordinatedSignalCount: 0
  };
}

function normalizeStringArray(values = [], maxItems = MAX_RECENT_ITEMS) {
  if (!Array.isArray(values)) return [];

  const out = [];
  for (const v of values) {
    const s = safeString(v, 200);
    if (!s) continue;

    if (!out.includes(s)) {
      out.push(s);
    }

    if (out.length >= maxItems) break;
  }

  return out;
}

function normalizeNumberArray(values = [], maxItems = MAX_RECENT_ITEMS) {
  if (!Array.isArray(values)) return [];

  const out = [];
  for (const v of values) {
    out.push(safeInt(v, 0, 0, 100));
    if (out.length >= maxItems) break;
  }

  return out;
}

function normalizeState(raw, actorType = "session", actorId = "") {
  const base = createDefaultState(actorType, actorId);
  const s = raw && typeof raw === "object" ? raw : {};

  return {
    actorType: normalizeKey(s.actorType || base.actorType),
    actorId: normalizeKey(s.actorId || base.actorId),

    updatedAt: safeInt(s.updatedAt, base.updatedAt, 0, Date.now() + 60000),
    createdAt: safeInt(s.createdAt, base.createdAt, 0, Date.now() + 60000),

    recentIps: normalizeStringArray(s.recentIps),
    recentRoutes: normalizeStringArray(s.recentRoutes),
    recentActions: normalizeStringArray(s.recentActions),
    recentRiskScores: normalizeNumberArray(s.recentRiskScores),

    loginCount: safeInt(s.loginCount),
    signupCount: safeInt(s.signupCount),
    passwordResetCount: safeInt(s.passwordResetCount),
    writeActionCount: safeInt(s.writeActionCount),

    suspiciousBurstCount: safeInt(s.suspiciousBurstCount),
    ipChangeCount: safeInt(s.ipChangeCount),
    routeSpreadCount: safeInt(s.routeSpreadCount),
    exploitSignalCount: safeInt(s.exploitSignalCount),
    breachSignalCount: safeInt(s.breachSignalCount),
    replaySignalCount: safeInt(s.replaySignalCount),
    coordinatedSignalCount: safeInt(s.coordinatedSignalCount)
  };
}

function applyStateDecay(state, now = Date.now()) {
  const normalized = { ...state };
  const updatedAt = safeInt(normalized.updatedAt, now, 0, now);
  const elapsed = Math.max(0, now - updatedAt);

  if (elapsed < ANOMALY_DECAY_WINDOW_MS) {
    return normalized;
  }

  const windows = Math.floor(elapsed / ANOMALY_DECAY_WINDOW_MS);

  normalized.ipChangeCount = Math.max(0, normalized.ipChangeCount - windows);
  normalized.routeSpreadCount = Math.max(0, normalized.routeSpreadCount - windows);
  normalized.exploitSignalCount = Math.max(0, normalized.exploitSignalCount - windows);
  normalized.breachSignalCount = Math.max(0, normalized.breachSignalCount - windows);
  normalized.replaySignalCount = Math.max(0, normalized.replaySignalCount - windows);
  normalized.coordinatedSignalCount = Math.max(0, normalized.coordinatedSignalCount - windows);
  normalized.suspiciousBurstCount = Math.max(0, normalized.suspiciousBurstCount - windows);
  normalized.updatedAt = now;

  return normalized;
}

/* ------------------------------------------------ */
/* REDIS STORAGE */
/* ------------------------------------------------ */

async function getStoredState(env, actorType, actorId) {
  const redis = getRedis(env);

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
      return normalizeState(parsed, safeActorType, safeActorId);
    }

    if (typeof raw === "object") {
      return normalizeState(raw, safeActorType, safeActorId);
    }

    return createDefaultState(safeActorType, safeActorId);
  } catch (err) {
    console.error("Anomaly state read failed:", err);
    return createDefaultState(safeActorType, safeActorId);
  }
}

async function storeState(env, state) {
  const redis = getRedis(env);

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

    await redis.set(
      key,
      JSON.stringify(normalized),
      { ex: ANOMALY_STATE_TTL_SECONDS }
    );

    return true;
  } catch (err) {
    console.error("Anomaly state write failed:", err);
    return false;
  }
}

/* ------------------------------------------------ */
/* ANOMALY SCORE */
/* ------------------------------------------------ */

function getLevel(score) {
  const s = safeInt(score, 0, 0, 100);

  if (s >= 90) return "critical";
  if (s >= 70) return "high";
  if (s >= 40) return "medium";
  return "low";
}

function getAction(score, criticalSignals = 0) {
  const s = safeInt(score, 0, 0, 100);
  const critical = safeInt(criticalSignals, 0, 0, 100);

  if (critical >= 2 || s >= 90) return "block";
  if (s >= 70) return "challenge";
  if (s >= 40) return "throttle";
  return "allow";
}

function pushReason(list, reason) {
  const r = normalizeReason(reason);
  if (!r) return;

  if (!list.includes(r)) {
    list.push(r);
  }
}

/* ------------------------------------------------ */
/* MAIN ENGINE */
/* ------------------------------------------------ */

export async function evaluateAnomalyDetection({
  env = {},

  actorType = "session",
  actorId = "",

  ip = "",
  route = "",
  routeSensitivity = "normal",

  riskScore = 0,

  isWriteAction = false,
  actionType = "",

  payloadThreatResult = null,
  abuseResult = null,
  rateLimitResult = null,
  freshnessResult = null,
  risk = null
} = {}) {
  const safeActorType = normalizeKey(actorType);
  const safeActorId = normalizeKey(actorId);

  if (!safeActorId) {
    return {
      anomalyScore: 0,
      level: "low",
      action: "allow",
      reasons: [],
      signals: {
        contextualPressure: 0,
        exploitPressure: 0,
        breachPressure: 0,
        replayPressure: 0,
        coordinatedPressure: 0,
        historicalPressure: 0
      },
      events: {
        exploitSignals: 0,
        breachSignals: 0,
        coordinatedSignals: 0,
        replaySignals: 0,
        criticalSignals: 0
      }
    };
  }

  const currentIp = normalizeIp(ip);
  const currentRoute = normalizeRoute(route);
  const currentActionType = normalizeActionType(actionType || "unknown");
  const normalizedRouteSensitivity = normalizeRouteSensitivity(routeSensitivity);
  const safeRisk = safeInt(riskScore || risk?.riskScore, 0, 0, 100);

  const payloadExploitSignals = safeInt(payloadThreatResult?.events?.exploitSignals, 0, 0, 100);
  const payloadBreachSignals = safeInt(payloadThreatResult?.events?.breachSignals, 0, 0, 100);
  const abuseBreachSignals = safeInt(abuseResult?.events?.breachSignals, 0, 0, 100);
  const abuseEndpointSpread = safeInt(abuseResult?.events?.endpointSpread, 0, 0, 100);
  const replaySignals = safeInt(freshnessResult?.events?.replaySignals, 0, 0, 100);
  const rateHardBlockSignals = safeInt(rateLimitResult?.events?.hardBlockSignals, 0, 0, 100);

  const previousState = applyStateDecay(
    await getStoredState(env, safeActorType, safeActorId),
    Date.now()
  );

  const now = Date.now();

  const nextState = normalizeState(
    {
      ...previousState,
      updatedAt: now,

      recentIps:
        currentIp
          ? [currentIp, ...previousState.recentIps.filter((v) => v !== currentIp)].slice(0, MAX_RECENT_ITEMS)
          : previousState.recentIps,

      recentRoutes:
        currentRoute
          ? [currentRoute, ...previousState.recentRoutes.filter((v) => v !== currentRoute)].slice(0, MAX_RECENT_ITEMS)
          : previousState.recentRoutes,

      recentActions:
        currentActionType
          ? [currentActionType, ...previousState.recentActions.filter((v) => v !== currentActionType)].slice(0, MAX_RECENT_ITEMS)
          : previousState.recentActions,

      recentRiskScores:
        [safeRisk, ...previousState.recentRiskScores].slice(0, MAX_RECENT_ITEMS),

      writeActionCount: safeInt(previousState.writeActionCount, 0) + (isWriteAction ? 1 : 0),
      exploitSignalCount: safeInt(previousState.exploitSignalCount, 0) + (payloadExploitSignals > 0 ? 1 : 0),
      breachSignalCount:
        safeInt(previousState.breachSignalCount, 0) +
        (payloadBreachSignals > 0 || abuseBreachSignals > 0 ? 1 : 0),
      replaySignalCount: safeInt(previousState.replaySignalCount, 0) + (replaySignals > 0 ? 1 : 0),
      coordinatedSignalCount:
        safeInt(previousState.coordinatedSignalCount, 0) +
        (abuseEndpointSpread >= 4 ? 1 : 0)
    },
    safeActorType,
    safeActorId
  );

  let score = 0;
  let criticalSignals = 0;
  const reasons = [];

  const signals = {
    contextualPressure: 0,
    exploitPressure: 0,
    breachPressure: 0,
    replayPressure: 0,
    coordinatedPressure: 0,
    historicalPressure: 0
  };

  if (safeRisk >= 80) {
    signals.contextualPressure += 25;
    pushReason(reasons, "anomaly:high_risk_alignment");
  } else if (safeRisk >= 60) {
    signals.contextualPressure += 12;
    pushReason(reasons, "anomaly:medium_risk_alignment");
  }

  if (
    currentIp &&
    previousState.recentIps.length > 0 &&
    !previousState.recentIps.includes(currentIp)
  ) {
    signals.contextualPressure += 20;
    nextState.ipChangeCount = safeInt(previousState.ipChangeCount, 0) + 1;
    pushReason(reasons, "anomaly:ip_change_detected");
  }

  if (
    currentRoute &&
    !previousState.recentRoutes.includes(currentRoute) &&
    previousState.recentRoutes.length >= 4
  ) {
    signals.coordinatedPressure += 10;
    nextState.routeSpreadCount = safeInt(previousState.routeSpreadCount, 0) + 1;
    pushReason(reasons, "anomaly:new_route_after_wide_spread");
  }

  if (isWriteAction) {
    signals.contextualPressure += 8;
    pushReason(reasons, "anomaly:write_action_pressure");
  }

  if (normalizedRouteSensitivity === "critical") {
    signals.contextualPressure += 10;
    pushReason(reasons, "anomaly:critical_route_context");
  } else if (normalizedRouteSensitivity === "high") {
    signals.contextualPressure += 5;
    pushReason(reasons, "anomaly:high_route_context");
  }

  if (payloadExploitSignals > 0) {
    signals.exploitPressure += 28;
    criticalSignals += 1;
    pushReason(reasons, "anomaly:exploit_signal_detected");
  }

  if (payloadBreachSignals > 0 || abuseBreachSignals > 0) {
    signals.breachPressure += 35;
    criticalSignals += 1;
    pushReason(reasons, "anomaly:breach_signal_detected");
  }

  if (replaySignals > 0) {
    signals.replayPressure += 18;
    pushReason(reasons, "anomaly:replay_signal_detected");
    if (normalizedRouteSensitivity === "critical") {
      criticalSignals += 1;
    }
  }

  if (abuseEndpointSpread >= 4) {
    signals.coordinatedPressure += 18;
    pushReason(reasons, "anomaly:coordinated_route_spread");
  }

  if (rateHardBlockSignals > 0) {
    signals.contextualPressure += 12;
    pushReason(reasons, "anomaly:rate_limit_hard_block_signal");
  }

  if (safeInt(previousState.ipChangeCount, 0) >= 2) {
    signals.historicalPressure += 10;
    pushReason(reasons, "anomaly:repeated_ip_change_history");
  }

  if (safeInt(previousState.routeSpreadCount, 0) >= 2) {
    signals.historicalPressure += 10;
    pushReason(reasons, "anomaly:route_spread_history");
  }

  if (safeInt(previousState.exploitSignalCount, 0) >= 1) {
    signals.historicalPressure += 15;
    criticalSignals += 1;
    pushReason(reasons, "anomaly:exploit_history");
  }

  if (safeInt(previousState.breachSignalCount, 0) >= 1) {
    signals.historicalPressure += 20;
    criticalSignals += 1;
    pushReason(reasons, "anomaly:breach_history");
  }

  if (safeInt(previousState.replaySignalCount, 0) >= 2) {
    signals.historicalPressure += 12;
    pushReason(reasons, "anomaly:replay_history");
  }

  if (safeInt(previousState.coordinatedSignalCount, 0) >= 1) {
    signals.historicalPressure += 15;
    pushReason(reasons, "anomaly:coordinated_history");
  }

  score =
    signals.contextualPressure +
    signals.exploitPressure +
    signals.breachPressure +
    signals.replayPressure +
    signals.coordinatedPressure +
    signals.historicalPressure;

  const anomalyScore = Math.min(100, Math.max(0, score));

  const result = {
    anomalyScore,
    level: getLevel(anomalyScore),
    action: getAction(anomalyScore, criticalSignals),
    reasons: reasons.slice(0, MAX_REASONS),
    signals,
    events: {
      exploitSignals: payloadExploitSignals > 0 ? 1 : 0,
      breachSignals: payloadBreachSignals > 0 || abuseBreachSignals > 0 ? 1 : 0,
      coordinatedSignals: abuseEndpointSpread >= 4 ? 1 : 0,
      replaySignals: replaySignals > 0 ? 1 : 0,
      criticalSignals: safeInt(criticalSignals, 0, 0, 100)
    }
  };

  const ok = await storeState(env, nextState);

  if (ok && anomalyScore >= 40) {
    try {
      await appendSecurityEvent(env, {
        type: "anomaly_detected",
        severity:
          result.level === "critical"
            ? "critical"
            : result.level === "high"
              ? "warning"
              : "info",
        action:
          result.action === "block" ||
          result.action === "challenge" ||
          result.action === "throttle"
            ? result.action
            : "observe",
        route: currentRoute,
        ip: currentIp,
        reason: result.reasons[0] || "anomaly_detected",
        message: "Behavioral anomaly detected for actor.",
        metadata: {
          actorType: safeActorType,
          actorId: safeActorId,
          anomalyScore: result.anomalyScore,
          contextualPressure: result.signals.contextualPressure,
          exploitPressure: result.signals.exploitPressure,
          breachPressure: result.signals.breachPressure,
          replayPressure: result.signals.replayPressure,
          coordinatedPressure: result.signals.coordinatedPressure,
          historicalPressure: result.signals.historicalPressure,
          exploitSignals: result.events.exploitSignals,
          breachSignals: result.events.breachSignals,
          coordinatedSignals: result.events.coordinatedSignals,
          replaySignals: result.events.replaySignals
        }
      });
    } catch (err) {
      console.error("Anomaly event write failed:", err);
    }
  }

  return result;
}
