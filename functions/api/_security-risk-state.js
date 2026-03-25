import { getRedis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const RISK_STATE_PREFIX = "security:risk-state";
const RISK_STATE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const RISK_STATE_TTL_SECONDS = Math.max(1, Math.ceil(RISK_STATE_TTL_MS / 1000));
const RISK_STATE_DECAY_WINDOW_MS = 6 * 60 * 60 * 1000;
const MAX_FUTURE_TIME_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_COUNTER_VALUE = 1_000_000;

const ALLOWED_ACTOR_TYPES = new Set(["session", "user", "ip"]);
const ALLOWED_LEVELS = new Set(["low", "medium", "high", "critical"]);
const ALLOWED_ACTIONS = new Set(["allow", "throttle", "challenge", "block"]);

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

function getNowMax() {
  return Date.now() + MAX_FUTURE_TIME_MS;
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

/* -------------------- NORMALIZATION -------------------- */

function normalizeActorType(value = "session") {
  const normalized = safeString(value || "session", 20).toLowerCase();
  return ALLOWED_ACTOR_TYPES.has(normalized) ? normalized : "session";
}

function normalizeLevel(value = "low") {
  const normalized = safeString(value || "low", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "low";
}

function normalizeAction(value = "allow") {
  const normalized = safeString(value || "allow", 20).toLowerCase();
  return ALLOWED_ACTIONS.has(normalized) ? normalized : "allow";
}

function normalizeActorId(value = "") {
  return safeString(value || "", 160).replace(/[^a-zA-Z0-9:_-]/g, "_");
}

function normalizeReasonList(reasons = []) {
  if (!Array.isArray(reasons)) return [];

  return reasons
    .slice(0, 20)
    .map((reason) => safeString(reason, 120))
    .filter(Boolean);
}

function buildRiskStateKey(actorType, actorId) {
  return `${RISK_STATE_PREFIX}:${normalizeActorType(actorType)}:${normalizeActorId(actorId)}`;
}

function getLevelFromScore(score) {
  const safeScore = safeInt(score, 0, 0, 100);

  if (safeScore >= 90) return "critical";
  if (safeScore >= 70) return "high";
  if (safeScore >= 40) return "medium";
  return "low";
}

function createDefaultRiskState(actorType = "session", actorId = "") {
  const now = Date.now();

  return {
    actorType: normalizeActorType(actorType),
    actorId: normalizeActorId(actorId),
    currentRiskScore: 0,
    currentRiskLevel: "low",
    lastAction: "allow",
    lastEvaluatedAt: now,
    createdAt: now,
    degraded: false,

    suspiciousEventCount: 0,
    challengeCount: 0,
    throttleCount: 0,
    blockCount: 0,
    hardBlockSignalCount: 0,

    exploitFlagCount: 0,
    breachFlagCount: 0,
    replayFlagCount: 0,
    coordinatedFlagCount: 0,

    trustedEventCount: 0,
    successfulAuthCount: 0,
    failedLoginCount: 0,
    failedSignupCount: 0,
    failedPasswordResetCount: 0,
    captchaFailureCount: 0,
    rateLimitHitCount: 0,
    lockoutCount: 0,

    lastReasonSummary: []
  };
}

function normalizeRiskState(raw, actorType = "session", actorId = "") {
  const base = createDefaultRiskState(actorType, actorId);
  const nowMax = getNowMax();
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    actorType: normalizeActorType(state.actorType || base.actorType),
    actorId: normalizeActorId(state.actorId || base.actorId),
    currentRiskScore: safeInt(state.currentRiskScore, base.currentRiskScore, 0, 100),
    currentRiskLevel: normalizeLevel(state.currentRiskLevel || base.currentRiskLevel),
    lastAction: normalizeAction(state.lastAction || base.lastAction),
    lastEvaluatedAt: safeInt(state.lastEvaluatedAt, base.lastEvaluatedAt, 0, nowMax),
    createdAt: safeInt(state.createdAt, base.createdAt, 0, nowMax),
    degraded: state.degraded === true,

    suspiciousEventCount: safeInt(state.suspiciousEventCount, 0),
    challengeCount: safeInt(state.challengeCount, 0),
    throttleCount: safeInt(state.throttleCount, 0),
    blockCount: safeInt(state.blockCount, 0),
    hardBlockSignalCount: safeInt(state.hardBlockSignalCount, 0),

    exploitFlagCount: safeInt(state.exploitFlagCount, 0),
    breachFlagCount: safeInt(state.breachFlagCount, 0),
    replayFlagCount: safeInt(state.replayFlagCount, 0),
    coordinatedFlagCount: safeInt(state.coordinatedFlagCount, 0),

    trustedEventCount: safeInt(state.trustedEventCount, 0),
    successfulAuthCount: safeInt(state.successfulAuthCount, 0),
    failedLoginCount: safeInt(state.failedLoginCount, 0),
    failedSignupCount: safeInt(state.failedSignupCount, 0),
    failedPasswordResetCount: safeInt(state.failedPasswordResetCount, 0),
    captchaFailureCount: safeInt(state.captchaFailureCount, 0),
    rateLimitHitCount: safeInt(state.rateLimitHitCount, 0),
    lockoutCount: safeInt(state.lockoutCount, 0),

    lastReasonSummary: normalizeReasonList(state.lastReasonSummary || [])
  };
}

function normalizeIncrements(input = {}) {
  const increments = input && typeof input === "object" ? input : {};

  return {
    suspiciousEventCount: safeInt(increments.suspiciousEventCount, 0),
    challengeCount: safeInt(increments.challengeCount, 0),
    throttleCount: safeInt(increments.throttleCount, 0),
    blockCount: safeInt(increments.blockCount, 0),
    hardBlockSignalCount: safeInt(increments.hardBlockSignalCount, 0),

    exploitFlagCount: safeInt(increments.exploitFlagCount, 0),
    breachFlagCount: safeInt(increments.breachFlagCount, 0),
    replayFlagCount: safeInt(increments.replayFlagCount, 0),
    coordinatedFlagCount: safeInt(increments.coordinatedFlagCount, 0),

    trustedEventCount: safeInt(increments.trustedEventCount, 0),
    successfulAuthCount: safeInt(increments.successfulAuthCount, 0),
    failedLoginCount: safeInt(increments.failedLoginCount, 0),
    failedSignupCount: safeInt(increments.failedSignupCount, 0),
    failedPasswordResetCount: safeInt(increments.failedPasswordResetCount, 0),
    captchaFailureCount: safeInt(increments.captchaFailureCount, 0),
    rateLimitHitCount: safeInt(increments.rateLimitHitCount, 0),
    lockoutCount: safeInt(increments.lockoutCount, 0)
  };
}

function normalizeRiskResult(riskResult = {}) {
  const result = riskResult && typeof riskResult === "object" ? riskResult : {};
  const signals = result.signals && typeof result.signals === "object" ? result.signals : {};
  const events = result.events && typeof result.events === "object" ? result.events : {};

  const exploitSignalTotal =
    safeInt(result.exploitSignals, 0) +
    safeInt(events.exploitSignals, 0) +
    (safeInt(signals.exploitPressure, 0, 0, 100) > 0 ? 1 : 0);

  const breachSignalTotal =
    safeInt(result.breachSignals, 0) +
    safeInt(events.breachSignals, 0) +
    (safeInt(signals.breachPressure, 0, 0, 100) > 0 ? 1 : 0);

  const replaySignalTotal =
    safeInt(result.replaySignals, 0) +
    safeInt(events.replaySignals, 0) +
    (safeInt(signals.replayPressure, 0, 0, 100) > 0 ? 1 : 0);

  const coordinatedSignalTotal =
    safeInt(result.coordinatedSignals, 0) +
    safeInt(events.coordinatedSignals, 0) +
    (safeInt(signals.routePressure, 0, 0, 100) >= 12 ? 1 : 0);

  return {
    riskScore: safeInt(result.riskScore, 0, 0, 100),
    level: normalizeLevel(result.level || getLevelFromScore(result.riskScore)),
    finalAction: normalizeAction(result.finalAction || result.action || "allow"),
    reasons: normalizeReasonList(Array.isArray(result.reasons) ? result.reasons : []),
    criticalAttackLikely: result.criticalAttackLikely === true,
    degraded: result.degraded === true,

    hardBlockSignals:
      safeInt(result.hardBlockSignals, 0) +
      safeInt(events.hardBlockSignals, 0),

    exploitSignals: exploitSignalTotal > 0 ? 1 : 0,
    breachSignals: breachSignalTotal > 0 ? 1 : 0,
    replaySignals: replaySignalTotal > 0 ? 1 : 0,
    coordinatedSignals: coordinatedSignalTotal > 0 ? 1 : 0
  };
}

/* -------------------- STORAGE -------------------- */

function applyTimeDecay(state, now = Date.now()) {
  const normalized = { ...state };
  const lastEvaluatedAt = safeInt(normalized.lastEvaluatedAt, now, 0, now);
  const elapsed = Math.max(0, now - lastEvaluatedAt);

  if (elapsed < RISK_STATE_DECAY_WINDOW_MS) {
    return normalized;
  }

  const windows = Math.floor(elapsed / RISK_STATE_DECAY_WINDOW_MS);
  const scoreDecay = windows * 8;
  const suspicionDecay = windows;
  const trustGain = windows;

  normalized.currentRiskScore = Math.max(0, normalized.currentRiskScore - scoreDecay);
  normalized.suspiciousEventCount = Math.max(
    0,
    normalized.suspiciousEventCount - suspicionDecay
  );

  if (normalized.currentRiskScore <= 20) {
    normalized.blockCount = Math.max(0, normalized.blockCount - 1);
    normalized.challengeCount = Math.max(0, normalized.challengeCount - 1);
    normalized.throttleCount = Math.max(0, normalized.throttleCount - 1);
  }

  normalized.trustedEventCount = Math.min(
    MAX_COUNTER_VALUE,
    normalized.trustedEventCount + trustGain
  );

  normalized.currentRiskLevel = getLevelFromScore(normalized.currentRiskScore);

  return normalized;
}

async function getStoredRiskState(env, actorType, actorId) {
  const redis = getRedis(env);

  const safeActorType = normalizeActorType(actorType);
  const safeActorId = normalizeActorId(actorId);

  if (!safeActorId) {
    return createDefaultRiskState(safeActorType, safeActorId);
  }

  try {
    const key = buildRiskStateKey(safeActorType, safeActorId);
    const raw = await redis.get(key);

    if (!raw) {
      return createDefaultRiskState(safeActorType, safeActorId);
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      if (!parsed || typeof parsed !== "object") {
        return createDefaultRiskState(safeActorType, safeActorId);
      }
      return normalizeRiskState(parsed, safeActorType, safeActorId);
    }

    if (typeof raw === "object") {
      return normalizeRiskState(raw, safeActorType, safeActorId);
    }

    return createDefaultRiskState(safeActorType, safeActorId);
  } catch (error) {
    console.error("Risk state read failed:", error);
    return createDefaultRiskState(safeActorType, safeActorId);
  }
}

async function storeRiskState(env, state) {
  const redis = getRedis(env);

  const normalized = normalizeRiskState(
    state,
    state?.actorType || "session",
    state?.actorId || ""
  );

  if (!normalized.actorId) {
    return false;
  }

  try {
    const key = buildRiskStateKey(normalized.actorType, normalized.actorId);
    await redis.set(key, JSON.stringify(normalized), {
      ex: RISK_STATE_TTL_SECONDS
    });
    return true;
  } catch (error) {
    console.error("Risk state write failed:", error);
    return false;
  }
}

/* -------------------- EVENTING -------------------- */

function buildMergedReasons(existing = [], incoming = []) {
  const merged = [...normalizeReasonList(existing)];

  for (const reason of normalizeReasonList(incoming)) {
    if (!merged.includes(reason)) {
      merged.push(reason);
    }
  }

  return merged.slice(0, 20);
}

function shouldRecordRiskChange(previousState, nextState) {
  return (
    previousState.currentRiskLevel !== nextState.currentRiskLevel ||
    previousState.lastAction !== nextState.lastAction ||
    previousState.degraded !== nextState.degraded ||
    Math.abs(previousState.currentRiskScore - nextState.currentRiskScore) >= 15
  );
}

function getRiskEventSeverity(state) {
  if (state.currentRiskLevel === "critical" || state.lastAction === "block") {
    return "critical";
  }
  if (state.currentRiskLevel === "high" || state.lastAction === "challenge") {
    return "warning";
  }
  return "info";
}

function getRiskEventAction(state) {
  if (
    state.lastAction === "block" ||
    state.lastAction === "challenge" ||
    state.lastAction === "throttle"
  ) {
    return state.lastAction;
  }
  return "observe";
}

async function recordRiskStateEvent(env, previousState, nextState, reason = "risk_state_updated") {
  try {
    await appendSecurityEvent(env, {
      type: "risk_state_updated",
      severity: getRiskEventSeverity(nextState),
      action: getRiskEventAction(nextState),
      mode: "",
      reason: safeString(reason, 120),
      message: "Persistent actor risk state updated.",
      metadata: {
        actorType: nextState.actorType,
        actorId: nextState.actorId,
        previousRiskScore: previousState.currentRiskScore,
        nextRiskScore: nextState.currentRiskScore,
        previousRiskLevel: previousState.currentRiskLevel,
        nextRiskLevel: nextState.currentRiskLevel,
        lastAction: nextState.lastAction,
        degraded: nextState.degraded === true,
        suspiciousEventCount: nextState.suspiciousEventCount,
        challengeCount: nextState.challengeCount,
        throttleCount: nextState.throttleCount,
        blockCount: nextState.blockCount,
        hardBlockSignalCount: nextState.hardBlockSignalCount,
        exploitFlagCount: nextState.exploitFlagCount,
        breachFlagCount: nextState.breachFlagCount,
        replayFlagCount: nextState.replayFlagCount,
        coordinatedFlagCount: nextState.coordinatedFlagCount
      }
    });
  } catch (error) {
    console.error("Risk state event write failed:", error);
  }
}

/* -------------------- PUBLIC API -------------------- */

export async function getRiskState({
  env = {},
  actorType = "session",
  actorId = ""
} = {}) {
  const rawState = await getStoredRiskState(env, actorType, actorId);
  const decayedState = applyTimeDecay(rawState, Date.now());

  const shouldPersistDecay =
    decayedState.actorId &&
    (
      decayedState.currentRiskScore !== rawState.currentRiskScore ||
      decayedState.suspiciousEventCount !== rawState.suspiciousEventCount ||
      decayedState.blockCount !== rawState.blockCount ||
      decayedState.challengeCount !== rawState.challengeCount ||
      decayedState.throttleCount !== rawState.throttleCount ||
      decayedState.trustedEventCount !== rawState.trustedEventCount
    );

  if (shouldPersistDecay) {
    decayedState.lastEvaluatedAt = Date.now();
    await storeRiskState(env, decayedState);
  }

  return decayedState;
}

export async function updateRiskState({
  env = {},
  actorType = "session",
  actorId = "",
  riskResult = null,
  reason = "",
  increments = {}
} = {}) {
  const safeActorType = normalizeActorType(actorType);
  const safeActorId = normalizeActorId(actorId);

  if (!safeActorId) {
    return {
      ok: false,
      state: createDefaultRiskState(safeActorType, safeActorId)
    };
  }

  const now = Date.now();
  const currentState = applyTimeDecay(
    await getStoredRiskState(env, safeActorType, safeActorId),
    now
  );

  const normalizedRiskResult = normalizeRiskResult(riskResult);
  const normalizedIncrements = normalizeIncrements(increments);

  const nextRiskScore = safeInt(
    normalizedRiskResult.riskScore,
    currentState.currentRiskScore,
    0,
    100
  );
  const nextRiskLevel = normalizeLevel(
    normalizedRiskResult.level || getLevelFromScore(nextRiskScore)
  );
  const nextAction = normalizeAction(
    normalizedRiskResult.finalAction || currentState.lastAction || "allow"
  );

  const nextState = normalizeRiskState(
    {
      ...currentState,
      actorType: safeActorType,
      actorId: safeActorId,
      currentRiskScore: nextRiskScore,
      currentRiskLevel: nextRiskLevel,
      lastAction: nextAction,
      lastEvaluatedAt: now,
      degraded: normalizedRiskResult.degraded === true,

      suspiciousEventCount:
        currentState.suspiciousEventCount +
        normalizedIncrements.suspiciousEventCount,

      challengeCount:
        currentState.challengeCount +
        normalizedIncrements.challengeCount,

      throttleCount:
        currentState.throttleCount +
        normalizedIncrements.throttleCount,

      blockCount:
        currentState.blockCount +
        normalizedIncrements.blockCount,

      hardBlockSignalCount:
        currentState.hardBlockSignalCount +
        normalizedRiskResult.hardBlockSignals +
        normalizedIncrements.hardBlockSignalCount,

      exploitFlagCount:
        currentState.exploitFlagCount +
        normalizedIncrements.exploitFlagCount +
        normalizedRiskResult.exploitSignals,

      breachFlagCount:
        currentState.breachFlagCount +
        normalizedIncrements.breachFlagCount +
        normalizedRiskResult.breachSignals,

      replayFlagCount:
        currentState.replayFlagCount +
        normalizedIncrements.replayFlagCount +
        normalizedRiskResult.replaySignals,

      coordinatedFlagCount:
        currentState.coordinatedFlagCount +
        normalizedIncrements.coordinatedFlagCount +
        normalizedRiskResult.coordinatedSignals,

      trustedEventCount:
        currentState.trustedEventCount +
        normalizedIncrements.trustedEventCount,

      successfulAuthCount:
        currentState.successfulAuthCount +
        normalizedIncrements.successfulAuthCount,

      failedLoginCount:
        currentState.failedLoginCount +
        normalizedIncrements.failedLoginCount,

      failedSignupCount:
        currentState.failedSignupCount +
        normalizedIncrements.failedSignupCount,

      failedPasswordResetCount:
        currentState.failedPasswordResetCount +
        normalizedIncrements.failedPasswordResetCount,

      captchaFailureCount:
        currentState.captchaFailureCount +
        normalizedIncrements.captchaFailureCount,

      rateLimitHitCount:
        currentState.rateLimitHitCount +
        normalizedIncrements.rateLimitHitCount,

      lockoutCount:
        currentState.lockoutCount +
        normalizedIncrements.lockoutCount,

      lastReasonSummary: buildMergedReasons(
        currentState.lastReasonSummary,
        normalizedRiskResult.reasons.length
          ? normalizedRiskResult.reasons
          : [reason]
      )
    },
    safeActorType,
    safeActorId
  );

  const ok = await storeRiskState(env, nextState);

  if (ok && shouldRecordRiskChange(currentState, nextState)) {
    await recordRiskStateEvent(
      env,
      currentState,
      nextState,
      reason || "risk_state_updated"
    );
  }

  return {
    ok,
    state: nextState
  };
}

export async function clearRiskState({
  env = {},
  actorType = "session",
  actorId = "",
  reason = "manual_clear"
} = {}) {
  const safeActorType = normalizeActorType(actorType);
  const safeActorId = normalizeActorId(actorId);

  if (!safeActorId) {
    return {
      ok: false,
      state: createDefaultRiskState(safeActorType, safeActorId)
    };
  }

  const previousState = await getStoredRiskState(env, safeActorType, safeActorId);
  const nextState = createDefaultRiskState(safeActorType, safeActorId);
  const ok = await storeRiskState(env, nextState);

  if (ok) {
    try {
      await appendSecurityEvent(env, {
        type: "risk_state_cleared",
        severity: "info",
        action: "observe",
        reason: safeString(reason, 120),
        message: "Persistent actor risk state was cleared.",
        metadata: {
          actorType: safeActorType,
          actorId: safeActorId,
          previousRiskScore: previousState.currentRiskScore,
          previousRiskLevel: previousState.currentRiskLevel
        }
      });
    } catch (error) {
      console.error("Risk state clear event write failed:", error);
    }
  }

  return {
    ok,
    state: nextState
  };
}
