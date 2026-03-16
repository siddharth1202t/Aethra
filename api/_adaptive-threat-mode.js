import { redis } from "./_redis.js";
import { getContainmentState, setContainmentState } from "./_security-containment.js";

const ADAPTIVE_MODE_KEY = "security:adaptive-mode";
const ADAPTIVE_MODE_TTL_MS = 24 * 60 * 60 * 1000;
const ADAPTIVE_MODE_WINDOW_MS = 30 * 60 * 1000;

const ALLOWED_MODES = new Set([
  "normal",
  "elevated",
  "defense",
  "lockdown"
]);

function safeString(value, maxLength = 200) {
  return String(value || "").slice(0, maxLength);
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

function normalizeMode(mode = "") {
  const normalized = safeString(mode || "normal", 30).toLowerCase();
  return ALLOWED_MODES.has(normalized) ? normalized : "normal";
}

function createDefaultAdaptiveState() {
  return {
    mode: "normal",
    updatedAt: Date.now(),
    windowStartedAt: Date.now(),
    totalSignals: 0,
    criticalSignals: 0,
    blockSignals: 0,
    challengeSignals: 0,
    repeatedOffenderSignals: 0,
    lockdownTriggers: 0,
    lastReason: ""
  };
}

function normalizeAdaptiveState(raw) {
  const base = createDefaultAdaptiveState();
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    mode: normalizeMode(state.mode || base.mode),
    updatedAt: safeInt(state.updatedAt, base.updatedAt, 0, Date.now() + 60_000),
    windowStartedAt: safeInt(
      state.windowStartedAt,
      base.windowStartedAt,
      0,
      Date.now() + 60_000
    ),
    totalSignals: safeInt(state.totalSignals, 0, 0, 1_000_000),
    criticalSignals: safeInt(state.criticalSignals, 0, 0, 1_000_000),
    blockSignals: safeInt(state.blockSignals, 0, 0, 1_000_000),
    challengeSignals: safeInt(state.challengeSignals, 0, 0, 1_000_000),
    repeatedOffenderSignals: safeInt(state.repeatedOffenderSignals, 0, 0, 1_000_000),
    lockdownTriggers: safeInt(state.lockdownTriggers, 0, 0, 1_000_000),
    lastReason: safeString(state.lastReason || "", 300)
  };
}

async function getStoredAdaptiveState() {
  try {
    const raw = await redis.get(ADAPTIVE_MODE_KEY);

    if (!raw) {
      return createDefaultAdaptiveState();
    }

    if (typeof raw === "string") {
      return normalizeAdaptiveState(JSON.parse(raw));
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

async function storeAdaptiveState(state) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(ADAPTIVE_MODE_TTL_MS / 1000));
    await redis.set(ADAPTIVE_MODE_KEY, JSON.stringify(state), { ex: ttlSeconds });
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
  state.lastReason = "";
}

function decideAdaptiveMode(state) {
  if (
    state.criticalSignals >= 5 ||
    state.blockSignals >= 8 ||
    state.lockdownTriggers >= 2
  ) {
    return {
      mode: "lockdown",
      reason: "critical_attack_pressure"
    };
  }

  if (
    state.blockSignals >= 4 ||
    state.repeatedOffenderSignals >= 5 ||
    state.criticalSignals >= 3
  ) {
    return {
      mode: "defense",
      reason: "sustained_attack_activity"
    };
  }

  if (
    state.challengeSignals >= 5 ||
    state.totalSignals >= 10
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

async function applyContainmentForMode(mode, reason) {
  if (mode === "lockdown") {
    return setContainmentState({
      mode: "lockdown",
      reason,
      durationMs: 30 * 60 * 1000
    });
  }

  if (mode === "defense") {
    return setContainmentState({
      mode: "elevated",
      reason,
      durationMs: 20 * 60 * 1000,
      flags: {
        freezeRegistrations: true,
        disableUploads: true,
        forceCaptcha: true
      }
    });
  }

  if (mode === "elevated") {
    return setContainmentState({
      mode: "elevated",
      reason,
      durationMs: 15 * 60 * 1000,
      flags: {
        forceCaptcha: true
      }
    });
  }

  return {
    ok: true,
    state: await getContainmentState()
  };
}

export async function evaluateAdaptiveThreatMode({
  risk = null,
  threatResult = null,
  abuseResult = null,
  botResult = null
} = {}) {
  const now = Date.now();
  const state = await getStoredAdaptiveState();

  if (now - safeInt(state.windowStartedAt, now, 0, now) > ADAPTIVE_MODE_WINDOW_MS) {
    resetWindow(state, now);
  }

  state.updatedAt = now;
  state.totalSignals += 1;

  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);
  const riskAction = safeString(risk?.finalAction || risk?.action || "allow", 20);
  const threatScore = safeInt(threatResult?.threatScore, 0, 0, 100);
  const abuseScore = safeInt(abuseResult?.abuseScore, 0, 0, 100);
  const botScore = safeInt(botResult?.riskScore, 0, 0, 100);

  if (riskAction === "block") {
    state.blockSignals += 1;
  }

  if (riskAction === "challenge") {
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
    safeInt(threatResult?.events?.blockEvents, 0, 0, 1_000_000) >= 2 ||
    safeInt(threatResult?.events?.hardBlockSignals, 0, 0, 1_000_000) >= 2 ||
    safeInt(threatResult?.events?.criticalRouteHits, 0, 0, 1_000_000) >= 5
  ) {
    state.repeatedOffenderSignals += 1;
  }

  if (
    riskScore >= 95 ||
    threatScore >= 95 ||
    safeInt(threatResult?.events?.hardBlockSignals, 0, 0, 1_000_000) >= 3
  ) {
    state.lockdownTriggers += 1;
  }

  const decision = decideAdaptiveMode(state);
  const previousMode = state.mode;
  state.mode = decision.mode;
  state.lastReason = decision.reason;

  await storeAdaptiveState(state);

  let containment = null;
  if (decision.mode !== "normal") {
    containment = await applyContainmentForMode(decision.mode, decision.reason);
  }

  return {
    mode: state.mode,
    previousMode,
    changed: previousMode !== state.mode,
    reason: state.lastReason,
    windowStartedAt: state.windowStartedAt,
    updatedAt: state.updatedAt,
    counters: {
      totalSignals: safeInt(state.totalSignals, 0, 0, 1_000_000),
      criticalSignals: safeInt(state.criticalSignals, 0, 0, 1_000_000),
      blockSignals: safeInt(state.blockSignals, 0, 0, 1_000_000),
      challengeSignals: safeInt(state.challengeSignals, 0, 0, 1_000_000),
      repeatedOffenderSignals: safeInt(state.repeatedOffenderSignals, 0, 0, 1_000_000),
      lockdownTriggers: safeInt(state.lockdownTriggers, 0, 0, 1_000_000)
    },
    containment: containment?.state || null
  };
}

export async function getAdaptiveThreatMode() {
  const state = await getStoredAdaptiveState();

  return {
    mode: state.mode,
    updatedAt: state.updatedAt,
    windowStartedAt: state.windowStartedAt,
    lastReason: state.lastReason,
    counters: {
      totalSignals: state.totalSignals,
      criticalSignals: state.criticalSignals,
      blockSignals: state.blockSignals,
      challengeSignals: state.challengeSignals,
      repeatedOffenderSignals: state.repeatedOffenderSignals,
      lockdownTriggers: state.lockdownTriggers
    }
  };
}

export async function resetAdaptiveThreatMode() {
  const state = createDefaultAdaptiveState();
  const ok = await storeAdaptiveState(state);

  return {
    ok,
    state
  };
}
