import { getRedis } from "./_redis.js";
import {
  getContainmentState,
  setContainmentState
} from "./_security-containment.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const ADAPTIVE_MODE_KEY = "security:adaptive-mode";
const ADAPTIVE_MODE_TTL_MS = 24 * 60 * 60 * 1000;
const ADAPTIVE_MODE_WINDOW_MS = 30 * 60 * 1000;
const ADAPTIVE_MODE_TTL_SECONDS = Math.max(
  1,
  Math.ceil(ADAPTIVE_MODE_TTL_MS / 1000)
);

const ALLOWED_MODES = new Set([
  "normal",
  "elevated",
  "defense",
  "lockdown"
]);

const ALLOWED_ACTIONS = new Set([
  "allow",
  "challenge",
  "throttle",
  "block"
]);

const ALLOWED_ROUTE_SENSITIVITY = new Set([
  "normal",
  "high",
  "critical"
]);

const MAX_COUNTER_VALUE = 1_000_000;
const MAX_TIMESTAMP_FUTURE_SKEW_MS = 60_000;

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

function normalizeMode(mode = "") {
  const normalized = safeString(mode || "normal", 30).toLowerCase();
  return ALLOWED_MODES.has(normalized) ? normalized : "normal";
}

function normalizeAction(action = "") {
  const normalized = safeString(action || "allow", 20).toLowerCase();
  return ALLOWED_ACTIONS.has(normalized) ? normalized : "allow";
}

function normalizeReason(value = "") {
  return safeString(value || "", 300).replace(/[^a-z0-9_:-]/gi, "_");
}

function normalizeRouteSensitivity(value = "normal") {
  const normalized = safeString(value || "normal", 20).toLowerCase();
  return ALLOWED_ROUTE_SENSITIVITY.has(normalized) ? normalized : "normal";
}

function createDefaultAdaptiveState() {
  const now = Date.now();

  return {
    mode: "normal",
    updatedAt: now,
    windowStartedAt: now,

    totalSignals: 0,
    criticalSignals: 0,
    blockSignals: 0,
    challengeSignals: 0,
    repeatedOffenderSignals: 0,
    lockdownTriggers: 0,
    highRiskStateSignals: 0,
    routePressureSignals: 0,

    burstSignals: 0,
    coordinatedAttackSignals: 0,
    breachAttemptSignals: 0,
    exploitAttemptSignals: 0,

    lastReason: "stable_activity"
  };
}

function normalizeAdaptiveState(raw) {
  const base = createDefaultAdaptiveState();
  const nowMax = Date.now() + MAX_TIMESTAMP_FUTURE_SKEW_MS;
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    mode: normalizeMode(state.mode || base.mode),
    updatedAt: safeInt(state.updatedAt, base.updatedAt, 0, nowMax),
    windowStartedAt: safeInt(state.windowStartedAt, base.windowStartedAt, 0, nowMax),

    totalSignals: safeInt(state.totalSignals, 0),
    criticalSignals: safeInt(state.criticalSignals, 0),
    blockSignals: safeInt(state.blockSignals, 0),
    challengeSignals: safeInt(state.challengeSignals, 0),
    repeatedOffenderSignals: safeInt(state.repeatedOffenderSignals, 0),
    lockdownTriggers: safeInt(state.lockdownTriggers, 0),
    highRiskStateSignals: safeInt(state.highRiskStateSignals, 0),
    routePressureSignals: safeInt(state.routePressureSignals, 0),

    burstSignals: safeInt(state.burstSignals, 0),
    coordinatedAttackSignals: safeInt(state.coordinatedAttackSignals, 0),
    breachAttemptSignals: safeInt(state.breachAttemptSignals, 0),
    exploitAttemptSignals: safeInt(state.exploitAttemptSignals, 0),

    lastReason: normalizeReason(state.lastReason || base.lastReason)
  };
}

function normalizeCounters(state) {
  return {
    totalSignals: safeInt(state?.totalSignals, 0),
    criticalSignals: safeInt(state?.criticalSignals, 0),
    blockSignals: safeInt(state?.blockSignals, 0),
    challengeSignals: safeInt(state?.challengeSignals, 0),
    repeatedOffenderSignals: safeInt(state?.repeatedOffenderSignals, 0),
    lockdownTriggers: safeInt(state?.lockdownTriggers, 0),
    highRiskStateSignals: safeInt(state?.highRiskStateSignals, 0),
    routePressureSignals: safeInt(state?.routePressureSignals, 0),
    burstSignals: safeInt(state?.burstSignals, 0),
    coordinatedAttackSignals: safeInt(state?.coordinatedAttackSignals, 0),
    breachAttemptSignals: safeInt(state?.breachAttemptSignals, 0),
    exploitAttemptSignals: safeInt(state?.exploitAttemptSignals, 0)
  };
}

async function getStoredAdaptiveState(env = {}) {
  const redis = getRedis(env);

  try {
    const raw = await redis.get(ADAPTIVE_MODE_KEY);

    if (!raw) return createDefaultAdaptiveState();

    if (typeof raw === "string") {
      return normalizeAdaptiveState(safeJsonParse(raw, null));
    }

    if (typeof raw === "object") {
      return normalizeAdaptiveState(raw);
    }

    return createDefaultAdaptiveState();
  } catch (error) {
    console.error("Adaptive mode read failed:", error);
    return createDefaultAdaptiveState();
  }
}

async function storeAdaptiveState(env = {}, state) {
  const redis = getRedis(env);

  try {
    const normalized = normalizeAdaptiveState(state);
    await redis.set(ADAPTIVE_MODE_KEY, JSON.stringify(normalized), {
      ex: ADAPTIVE_MODE_TTL_SECONDS
    });
    return true;
  } catch (error) {
    console.error("Adaptive mode write failed:", error);
    return false;
  }
}

function resetWindow(state, now) {
  state.windowStartedAt = now;
  state.totalSignals = 0;
  state.criticalSignals = 0;
  state.blockSignals = 0;
  state.challengeSignals = 0;
  state.repeatedOffenderSignals = 0;
  state.lockdownTriggers = 0;
  state.highRiskStateSignals = 0;
  state.routePressureSignals = 0;
  state.burstSignals = 0;
  state.coordinatedAttackSignals = 0;
  state.breachAttemptSignals = 0;
  state.exploitAttemptSignals = 0;
  state.lastReason = "stable_activity";
}

function hasWindowExpired(windowStartedAt, now) {
  const safeWindowStartedAt = safeInt(windowStartedAt, now, 0, now);
  return now - safeWindowStartedAt > ADAPTIVE_MODE_WINDOW_MS;
}

function decideAdaptiveMode(state) {
  // Level 9 / critical pressure path
  if (
    state.breachAttemptSignals >= 2 ||
    state.exploitAttemptSignals >= 3 ||
    state.coordinatedAttackSignals >= 4 ||
    state.lockdownTriggers >= 2 ||
    (state.criticalSignals >= 5 && state.blockSignals >= 4) ||
    (state.repeatedOffenderSignals >= 5 && state.highRiskStateSignals >= 3)
  ) {
    return {
      mode: "lockdown",
      reason: "critical_attack_pressure"
    };
  }

  // Level 7–8 sustained threat path
  if (
    state.blockSignals >= 4 ||
    state.repeatedOffenderSignals >= 5 ||
    state.criticalSignals >= 3 ||
    state.burstSignals >= 4 ||
    (state.highRiskStateSignals >= 3 && state.routePressureSignals >= 3)
  ) {
    return {
      mode: "defense",
      reason: "sustained_attack_activity"
    };
  }

  // Elevated suspicious path
  if (
    state.challengeSignals >= 5 ||
    state.totalSignals >= 10 ||
    state.routePressureSignals >= 4
  ) {
    return {
      mode: "elevated",
      reason: "increased_security_pressure"
    };
  }

  return {
    mode: "normal",
    reason: "stable_activity"
  };
}

function normalizeSecurityState(securityState = null) {
  if (!securityState || typeof securityState !== "object") {
    return null;
  }

  return {
    currentRiskScore: safeInt(securityState.currentRiskScore, 0, 0, 100),
    currentRiskLevel: safeString(securityState.currentRiskLevel || "low", 20).toLowerCase(),
    failedLoginCount: safeInt(securityState.failedLoginCount, 0),
    failedSignupCount: safeInt(securityState.failedSignupCount, 0),
    failedPasswordResetCount: safeInt(securityState.failedPasswordResetCount, 0),
    captchaFailureCount: safeInt(securityState.captchaFailureCount, 0),
    suspiciousEventCount: safeInt(securityState.suspiciousEventCount, 0),
    rateLimitHitCount: safeInt(securityState.rateLimitHitCount, 0),
    lockoutCount: safeInt(securityState.lockoutCount, 0),
    exploitFlagCount: safeInt(securityState.exploitFlagCount, 0),
    breachFlagCount: safeInt(securityState.breachFlagCount, 0)
  };
}

function shouldReturnToNormalContainment(currentContainment) {
  return (
    currentContainment?.mode !== "normal" ||
    currentContainment?.flags?.freezeRegistrations === true ||
    currentContainment?.flags?.disableProfileEdits === true ||
    currentContainment?.flags?.lockAdminWrites === true ||
    currentContainment?.flags?.disableUploads === true ||
    currentContainment?.flags?.forceCaptcha === true ||
    currentContainment?.flags?.readOnlyMode === true ||
    currentContainment?.flags?.lockdown === true
  );
}

async function syncContainmentToMode(env = {}, mode, reason) {
  const normalizedMode = normalizeMode(mode);
  const normalizedReason = normalizeReason(reason || "adaptive_sync");
  const currentContainment = await getContainmentState(env);

  if (normalizedMode === "lockdown") {
    return setContainmentState(env, {
      mode: "lockdown",
      reason: normalizedReason,
      durationMs: 30 * 60 * 1000,
      flags: {
        freezeRegistrations: true,
        disableProfileEdits: true,
        lockAdminWrites: true,
        disableUploads: true,
        forceCaptcha: true,
        readOnlyMode: true,
        lockdown: true
      }
    });
  }

  if (normalizedMode === "defense") {
    return setContainmentState(env, {
      mode: "elevated",
      reason: normalizedReason,
      durationMs: 20 * 60 * 1000,
      flags: {
        freezeRegistrations: true,
        disableProfileEdits: false,
        lockAdminWrites: false,
        disableUploads: true,
        forceCaptcha: true,
        readOnlyMode: false,
        lockdown: false
      }
    });
  }

  if (normalizedMode === "elevated") {
    return setContainmentState(env, {
      mode: "elevated",
      reason: normalizedReason,
      durationMs: 15 * 60 * 1000,
      flags: {
        freezeRegistrations: false,
        disableProfileEdits: false,
        lockAdminWrites: false,
        disableUploads: false,
        forceCaptcha: true,
        readOnlyMode: false,
        lockdown: false
      }
    });
  }

  if (shouldReturnToNormalContainment(currentContainment)) {
    return setContainmentState(env, {
      mode: "normal",
      reason: normalizedReason,
      durationMs: 5 * 60 * 1000,
      flags: {
        freezeRegistrations: false,
        disableProfileEdits: false,
        lockAdminWrites: false,
        disableUploads: false,
        forceCaptcha: false,
        readOnlyMode: false,
        lockdown: false
      }
    });
  }

  return {
    ok: true,
    state: currentContainment
  };
}

async function recordAdaptiveModeChange({
  env = {},
  previousMode,
  nextMode,
  reason,
  counters
}) {
  try {
    await appendSecurityEvent(env, {
      type: "adaptive_mode_changed",
      severity: nextMode === "lockdown" ? "critical" : nextMode === "defense" ? "high" : "warning",
      action: nextMode === "lockdown" ? "contain" : "observe",
      mode: nextMode,
      reason,
      message: "Adaptive threat mode changed.",
      metadata: {
        previousMode,
        nextMode,
        ...normalizeCounters(counters)
      }
    });
  } catch (error) {
    console.error("Adaptive mode event write failed:", error);
  }
}

function isBurstAttack(now, state) {
  const elapsed = Math.max(1, now - safeInt(state.windowStartedAt, now, 0, now));
  const perMinute = (safeInt(state.totalSignals, 0) * 60000) / elapsed;
  return perMinute >= 20;
}

export async function evaluateAdaptiveThreatMode({
  env = {},
  risk = null,
  threatResult = null,
  abuseResult = null,
  botResult = null,
  securityState = null,
  routeSensitivity = "normal"
} = {}) {
  const now = Date.now();
  const state = await getStoredAdaptiveState(env);

  if (hasWindowExpired(state.windowStartedAt, now)) {
    resetWindow(state, now);
  }

  state.updatedAt = now;
  state.totalSignals += 1;

  const normalizedSecurityState = normalizeSecurityState(securityState);
  const normalizedRouteSensitivity = normalizeRouteSensitivity(routeSensitivity);

  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);
  const riskAction = normalizeAction(risk?.finalAction || risk?.action || "allow");
  const threatScore = safeInt(threatResult?.threatScore, 0, 0, 100);
  const abuseScore = safeInt(abuseResult?.abuseScore, 0, 0, 100);
  const botScore = safeInt(botResult?.riskScore, 0, 0, 100);

  const blockEvents = safeInt(threatResult?.events?.blockEvents, 0);
  const hardBlockSignals = safeInt(threatResult?.events?.hardBlockSignals, 0);
  const criticalRouteHits = safeInt(threatResult?.events?.criticalRouteHits, 0);

  const exploitSignals = safeInt(threatResult?.events?.exploitSignals, 0);
  const breachSignals = safeInt(abuseResult?.events?.breachSignals, 0);
  const endpointSpread = safeInt(threatResult?.events?.endpointSpread, 0);

  if (riskAction === "block") {
    state.blockSignals += 1;
  }

  if (riskAction === "challenge" || riskAction === "throttle") {
    state.challengeSignals += 1;
  }

  if (
    riskScore >= 85 ||
    threatScore >= 85 ||
    abuseScore >= 70 ||
    botScore >= 70
  ) {
    state.criticalSignals += 1;
  }

  if (
    blockEvents >= 2 ||
    hardBlockSignals >= 2 ||
    criticalRouteHits >= 5
  ) {
    state.repeatedOffenderSignals += 1;
  }

  if (
    riskScore >= 95 ||
    threatScore >= 95 ||
    hardBlockSignals >= 3
  ) {
    state.lockdownTriggers += 1;
  }

  if (exploitSignals >= 1 || riskScore >= 98) {
    state.exploitAttemptSignals += 1;
  }

  if (breachSignals >= 1 || abuseScore >= 90) {
    state.breachAttemptSignals += 1;
  }

  if (endpointSpread >= 3 || criticalRouteHits >= 6) {
    state.coordinatedAttackSignals += 1;
  }

  if (normalizedRouteSensitivity === "critical") {
    state.routePressureSignals += 2;
  } else if (normalizedRouteSensitivity === "high") {
    state.routePressureSignals += 1;
  }

  if (normalizedSecurityState) {
    if (
      normalizedSecurityState.currentRiskScore >= 75 ||
      normalizedSecurityState.currentRiskLevel === "critical"
    ) {
      state.highRiskStateSignals += 2;
    } else if (
      normalizedSecurityState.currentRiskScore >= 45 ||
      normalizedSecurityState.currentRiskLevel === "high"
    ) {
      state.highRiskStateSignals += 1;
    }

    if (
      normalizedSecurityState.lockoutCount >= 2 ||
      normalizedSecurityState.suspiciousEventCount >= 5
    ) {
      state.repeatedOffenderSignals += 1;
    }

    if (
      normalizedSecurityState.failedLoginCount >= 5 ||
      normalizedSecurityState.captchaFailureCount >= 5 ||
      normalizedSecurityState.rateLimitHitCount >= 4
    ) {
      state.criticalSignals += 1;
    }

    if (normalizedSecurityState.exploitFlagCount >= 1) {
      state.exploitAttemptSignals += 1;
    }

    if (normalizedSecurityState.breachFlagCount >= 1) {
      state.breachAttemptSignals += 1;
    }
  }

  if (isBurstAttack(now, state)) {
    state.burstSignals += 1;
  }

  const previousMode = state.mode;
  const decision = decideAdaptiveMode(state);

  state.mode = decision.mode;
  state.lastReason = normalizeReason(decision.reason);

  await storeAdaptiveState(env, state);
  const containment = await syncContainmentToMode(env, state.mode, state.lastReason);

  const normalizedCounters = normalizeCounters(state);

  if (previousMode !== state.mode) {
    await recordAdaptiveModeChange({
      env,
      previousMode,
      nextMode: state.mode,
      reason: state.lastReason,
      counters: normalizedCounters
    });
  }

  return {
    mode: state.mode,
    previousMode,
    changed: previousMode !== state.mode,
    reason: state.lastReason,
    windowStartedAt: state.windowStartedAt,
    updatedAt: state.updatedAt,
    counters: normalizedCounters,
    containment: containment?.state || null,
    criticalAttackLikely:
      state.mode === "lockdown" ||
      normalizedCounters.breachAttemptSignals > 0 ||
      normalizedCounters.exploitAttemptSignals > 0
  };
}

export async function getAdaptiveThreatMode(env = {}) {
  const state = await getStoredAdaptiveState(env);

  return {
    mode: state.mode,
    updatedAt: state.updatedAt,
    windowStartedAt: state.windowStartedAt,
    lastReason: state.lastReason,
    counters: normalizeCounters(state)
  };
}

export async function getAdaptiveThreatModeSnapshot(env = {}) {
  return getAdaptiveThreatMode(env);
}

export async function resetAdaptiveThreatMode(env = {}) {
  const state = createDefaultAdaptiveState();
  const ok = await storeAdaptiveState(env, state);

  await syncContainmentToMode(env, "normal", "manual_reset");

  try {
    await appendSecurityEvent(env, {
      type: "adaptive_mode_reset",
      severity: "info",
      action: "observe",
      mode: "normal",
      reason: "manual_reset",
      message: "Adaptive threat mode was reset manually.",
      metadata: {
        mode: "normal"
      }
    });
  } catch (error) {
    console.error("Adaptive mode reset event write failed:", error);
  }

  return {
    ok,
    state
  };
}
