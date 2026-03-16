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

const ALLOWED_ACTIONS = new Set([
  "allow",
  "challenge",
  "throttle",
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
    lastReason: "stable_activity"
  };
}

function normalizeAdaptiveState(raw) {
  const base = createDefaultAdaptiveState();
  const nowMax = Date.now() + 60_000;
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    mode: normalizeMode(state.mode || base.mode),
    updatedAt: safeInt(state.updatedAt, base.updatedAt, 0, nowMax),
    windowStartedAt: safeInt(
      state.windowStartedAt,
      base.windowStartedAt,
      0,
      nowMax
    ),
    totalSignals: safeInt(state.totalSignals, 0, 0, 1_000_000),
    criticalSignals: safeInt(state.criticalSignals, 0, 0, 1_000_000),
    blockSignals: safeInt(state.blockSignals, 0, 0, 1_000_000),
    challengeSignals: safeInt(state.challengeSignals, 0, 0, 1_000_000),
    repeatedOffenderSignals: safeInt(state.repeatedOffenderSignals, 0, 0, 1_000_000),
    lockdownTriggers: safeInt(state.lockdownTriggers, 0, 0, 1_000_000),
    lastReason: normalizeReason(state.lastReason || base.lastReason)
  };
}

async function getStoredAdaptiveState() {
  try {
    const raw = await redis.get(ADAPTIVE_MODE_KEY);

    if (!raw) {
      return createDefaultAdaptiveState();
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      if (!parsed || typeof parsed !== "object") {
        return createDefaultAdaptiveState();
      }
      return normalizeAdaptiveState(parsed);
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
    const normalized = normalizeAdaptiveState(state);
    const ttlSeconds = Math.max(1, Math.ceil(ADAPTIVE_MODE_TTL_MS / 1000));
    await redis.set(ADAPTIVE_MODE_KEY, JSON.stringify(normalized), { ex: ttlSeconds });
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
  state.lastReason = "stable_activity";
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

async function syncContainmentToMode(mode, reason) {
  const normalizedMode = normalizeMode(mode);
  const normalizedReason = normalizeReason(reason || "adaptive_sync");
  const currentContainment = await getContainmentState();

  if (normalizedMode === "lockdown") {
    return setContainmentState({
      mode: "lockdown",
      reason: normalizedReason,
      durationMs: 30 * 60 * 1000
    });
  }

  if (normalizedMode === "defense") {
    return setContainmentState({
      mode: "elevated",
      reason: normalizedReason,
      durationMs: 20 * 60 * 1000,
      flags: {
        freezeRegistrations: true,
        disableUploads: true,
        forceCaptcha: true
      }
    });
  }

  if (normalizedMode === "elevated") {
    return setContainmentState({
      mode: "elevated",
      reason: normalizedReason,
      durationMs: 15 * 60 * 1000,
      flags: {
        freezeRegistrations: false,
        disableUploads: false,
        forceCaptcha: true
      }
    });
  }

  // Return to normal-safe containment defaults
  if (
    currentContainment?.mode !== "normal" ||
    currentContainment?.flags?.freezeRegistrations ||
    currentContainment?.flags?.disableUploads ||
    currentContainment?.flags?.forceCaptcha ||
    currentContainment?.flags?.readOnlyMode ||
    currentContainment?.flags?.lockdown
  ) {
    return setContainmentState({
      mode: "normal",
      reason: normalizedReason,
      durationMs: 5 * 60 * 1000,
      flags: {
        freezeRegistrations: false,
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

function hasWindowExpired(windowStartedAt, now) {
  const safeWindowStartedAt = safeInt(windowStartedAt, now, 0, now);
  return now - safeWindowStartedAt > ADAPTIVE_MODE_WINDOW_MS;
}

export async function evaluateAdaptiveThreatMode({
  risk = null,
  threatResult = null,
  abuseResult = null,
  botResult = null
} = {}) {
  const now = Date.now();
  const state = await getStoredAdaptiveState();

  if (hasWindowExpired(state.windowStartedAt, now)) {
    resetWindow(state, now);
  }

  state.updatedAt = now;
  state.totalSignals += 1;

  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);
  const riskAction = normalizeAction(risk?.finalAction || risk?.action || "allow");
  const threatScore = safeInt(threatResult?.threatScore, 0, 0, 100);
  const abuseScore = safeInt(abuseResult?.abuseScore, 0, 0, 100);
  const botScore = safeInt(botResult?.riskScore, 0, 0, 100);

  const blockEvents = safeInt(threatResult?.events?.blockEvents, 0, 0, 1_000_000);
  const hardBlockSignals = safeInt(threatResult?.events?.hardBlockSignals, 0, 0, 1_000_000);
  const criticalRouteHits = safeInt(threatResult?.events?.criticalRouteHits, 0, 0, 1_000_000);

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

  const decision = decideAdaptiveMode(state);
  const previousMode = state.mode;
  state.mode = decision.mode;
  state.lastReason = normalizeReason(decision.reason);

  await storeAdaptiveState(state);

  const containment = await syncContainmentToMode(state.mode, state.lastReason);

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
      totalSignals: safeInt(state.totalSignals, 0, 0, 1_000_000),
      criticalSignals: safeInt(state.criticalSignals, 0, 0, 1_000_000),
      blockSignals: safeInt(state.blockSignals, 0, 0, 1_000_000),
      challengeSignals: safeInt(state.challengeSignals, 0, 0, 1_000_000),
      repeatedOffenderSignals: safeInt(state.repeatedOffenderSignals, 0, 0, 1_000_000),
      lockdownTriggers: safeInt(state.lockdownTriggers, 0, 0, 1_000_000)
    }
  };
}

export async function resetAdaptiveThreatMode() {
  const state = createDefaultAdaptiveState();
  const ok = await storeAdaptiveState(state);

  await syncContainmentToMode("normal", "manual_reset");

  return {
    ok,
    state
  };
}
