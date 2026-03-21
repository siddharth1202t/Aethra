import { redis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const CONTAINMENT_KEY = "security:containment:global";
const CONTAINMENT_TTL_MS = 24 * 60 * 60 * 1000;
const CONTAINMENT_TTL_SECONDS = Math.max(
  1,
  Math.ceil(CONTAINMENT_TTL_MS / 1000)
);
const MAX_FUTURE_TIME_MS = 7 * 24 * 60 * 60 * 1000;

const ALLOWED_MODES = new Set([
  "normal",
  "elevated",
  "lockdown"
]);

const ALLOWED_FLAGS = new Set([
  "freezeRegistrations",
  "disableProfileEdits",
  "lockAdminWrites",
  "readOnlyMode",
  "disableUploads",
  "forceCaptcha",
  "lockdown"
]);

const MODE_RANK = {
  normal: 0,
  elevated: 1,
  lockdown: 2
};

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

function safeInt(value, fallback = 0, min = 0, max = getNowMax()) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeBoolean(value) {
  return value === true;
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

function normalizeRoute(value = "") {
  const raw = safeString(value || "", 300);
  if (!raw) return "";

  return raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, 200);
}

function normalizeActionType(value = "") {
  return safeString(value || "", 50).toLowerCase();
}

function createDefaultFlags() {
  return {
    freezeRegistrations: false,
    disableProfileEdits: false,
    lockAdminWrites: false,
    readOnlyMode: false,
    disableUploads: false,
    forceCaptcha: false,
    lockdown: false
  };
}

function sanitizeFlags(flags = {}) {
  const base = createDefaultFlags();
  const source = flags && typeof flags === "object" ? flags : {};
  const output = {};

  for (const key of ALLOWED_FLAGS) {
    output[key] = safeBoolean(source[key] ?? base[key]);
  }

  return output;
}

function getDefaultFlagsForMode(mode = "normal") {
  const normalizedMode = normalizeMode(mode);

  if (normalizedMode === "lockdown") {
    return {
      freezeRegistrations: true,
      disableProfileEdits: true,
      lockAdminWrites: true,
      readOnlyMode: true,
      disableUploads: true,
      forceCaptcha: true,
      lockdown: true
    };
  }

  if (normalizedMode === "elevated") {
    return {
      freezeRegistrations: false,
      disableProfileEdits: false,
      lockAdminWrites: false,
      readOnlyMode: false,
      disableUploads: false,
      forceCaptcha: true,
      lockdown: false
    };
  }

  return createDefaultFlags();
}

function createDefaultContainmentState() {
  return {
    mode: "normal",
    reason: "",
    updatedAt: Date.now(),
    expiresAt: 0,
    flags: createDefaultFlags()
  };
}

function normalizeContainmentState(raw) {
  const base = createDefaultContainmentState();
  const state = raw && typeof raw === "object" ? raw : {};
  const nowMax = getNowMax();

  const mode = normalizeMode(state.mode || base.mode);
  const reason = safeString(state.reason || "", 300);
  const updatedAt = safeInt(state.updatedAt, base.updatedAt, 0, nowMax);
  const expiresAt = safeInt(state.expiresAt, 0, 0, nowMax);

  let flags = sanitizeFlags({
    ...getDefaultFlagsForMode(mode),
    ...(state.flags || {})
  });

  if (mode === "normal") {
    return createDefaultContainmentState();
  }

  if (mode === "lockdown") {
    flags = {
      ...getDefaultFlagsForMode("lockdown"),
      ...flags,
      lockdown: true
    };
  }

  return {
    mode,
    reason,
    updatedAt,
    expiresAt,
    flags: sanitizeFlags(flags)
  };
}

function getStrongerMode(a = "normal", b = "normal") {
  const modeA = normalizeMode(a);
  const modeB = normalizeMode(b);
  return MODE_RANK[modeA] >= MODE_RANK[modeB] ? modeA : modeB;
}

function mergeFlagsForEscalation(currentFlags = {}, nextFlags = {}) {
  const current = sanitizeFlags(currentFlags);
  const next = sanitizeFlags(nextFlags);
  const output = {};

  for (const key of ALLOWED_FLAGS) {
    output[key] = current[key] || next[key];
  }

  return output;
}

function isContainmentExpired(state, now = Date.now()) {
  const expiresAt = safeInt(state?.expiresAt, 0, 0, getNowMax());
  return expiresAt > 0 && now > expiresAt;
}

function statesAreEquivalent(a = {}, b = {}) {
  const left = normalizeContainmentState(a);
  const right = normalizeContainmentState(b);

  if (left.mode !== right.mode) return false;
  if (left.reason !== right.reason) return false;
  if (left.expiresAt !== right.expiresAt) return false;

  for (const key of ALLOWED_FLAGS) {
    if (safeBoolean(left.flags?.[key]) !== safeBoolean(right.flags?.[key])) {
      return false;
    }
  }

  return true;
}

function buildContainmentMetadata(state = {}) {
  const normalized = normalizeContainmentState(state);

  return {
    mode: normalized.mode,
    expiresAt: normalized.expiresAt,
    freezeRegistrations: normalized.flags.freezeRegistrations,
    disableProfileEdits: normalized.flags.disableProfileEdits,
    lockAdminWrites: normalized.flags.lockAdminWrites,
    readOnlyMode: normalized.flags.readOnlyMode,
    disableUploads: normalized.flags.disableUploads,
    forceCaptcha: normalized.flags.forceCaptcha,
    lockdown: normalized.flags.lockdown
  };
}

async function recordContainmentEvent({
  type,
  severity,
  action,
  reason,
  previousState,
  nextState,
  message
}) {
  try {
    await appendSecurityEvent({
      type: safeString(type || "containment_updated", 60),
      severity: safeString(severity || "warning", 20).toLowerCase(),
      action: safeString(action || "contain", 30).toLowerCase(),
      mode: normalizeMode(nextState?.mode || "normal"),
      reason: safeString(reason || "", 300),
      message: safeString(message || "", 500),
      metadata: {
        previousMode: normalizeMode(previousState?.mode || "normal"),
        nextMode: normalizeMode(nextState?.mode || "normal"),
        previousExpiresAt: safeInt(previousState?.expiresAt, 0, 0, getNowMax()),
        nextExpiresAt: safeInt(nextState?.expiresAt, 0, 0, getNowMax()),
        ...buildContainmentMetadata(nextState)
      }
    });
  } catch (error) {
    console.error("Containment event write failed:", error);
  }
}

async function getStoredContainmentState() {
  try {
    const raw = await redis.get(CONTAINMENT_KEY);

    if (!raw) {
      return createDefaultContainmentState();
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      return normalizeContainmentState(parsed);
    }

    if (typeof raw === "object") {
      return normalizeContainmentState(raw);
    }

    return createDefaultContainmentState();
  } catch (error) {
    console.error("Containment read failed:", error);
    return createDefaultContainmentState();
  }
}

async function storeContainmentState(state) {
  try {
    const normalized = normalizeContainmentState(state);

    await redis.set(CONTAINMENT_KEY, JSON.stringify(normalized), {
      ex: CONTAINMENT_TTL_SECONDS
    });

    return true;
  } catch (error) {
    console.error("Containment write failed:", error);
    return false;
  }
}

export async function getContainmentState() {
  const state = await getStoredContainmentState();

  if (!isContainmentExpired(state)) {
    return normalizeContainmentState(state);
  }

  const previousState = normalizeContainmentState(state);
  const resetState = createDefaultContainmentState();

  await storeContainmentState(resetState);

  await recordContainmentEvent({
    type: "containment_expired_reset",
    severity: "info",
    action: "observe",
    reason: "containment_expired",
    previousState,
    nextState: resetState,
    message: "Containment state expired and was reset to normal."
  });

  return resetState;
}

export async function setContainmentState({
  mode = "normal",
  reason = "",
  durationMs = 0,
  flags = {},
  allowDowngrade = false
} = {}) {
  const requestedMode = normalizeMode(mode);
  const requestedReason = safeString(reason || "", 300);
  const requestedDurationMs = Math.max(0, safeNumber(durationMs, 0));
  const requestedFlags = sanitizeFlags(flags);
  const now = Date.now();

  const currentState = await getContainmentState();

  let finalMode = requestedMode;
  let finalFlags = {
    ...getDefaultFlagsForMode(requestedMode),
    ...requestedFlags
  };

  if (!allowDowngrade) {
    const strongerMode = getStrongerMode(currentState.mode, requestedMode);

    if (strongerMode !== requestedMode) {
      finalMode = strongerMode;
      finalFlags = mergeFlagsForEscalation(
        currentState.flags,
        {
          ...getDefaultFlagsForMode(requestedMode),
          ...requestedFlags
        }
      );
    } else if (
      strongerMode === currentState.mode &&
      strongerMode === requestedMode
    ) {
      finalFlags = mergeFlagsForEscalation(currentState.flags, finalFlags);
    }
  }

  if (finalMode === "normal") {
    finalFlags = createDefaultFlags();
  } else if (finalMode === "lockdown") {
    finalFlags = {
      ...getDefaultFlagsForMode("lockdown"),
      ...mergeFlagsForEscalation(getDefaultFlagsForMode("lockdown"), finalFlags),
      lockdown: true
    };
  } else {
    finalFlags = sanitizeFlags(finalFlags);
  }

  const nextState = normalizeContainmentState({
    mode: finalMode,
    reason: requestedReason,
    updatedAt: now,
    expiresAt: requestedDurationMs > 0 ? now + requestedDurationMs : 0,
    flags: finalFlags
  });

  const ok = await storeContainmentState(nextState);

  if (ok && !statesAreEquivalent(currentState, nextState)) {
    await recordContainmentEvent({
      type: nextState.mode === "normal" ? "containment_cleared" : "containment_updated",
      severity:
        nextState.mode === "lockdown"
          ? "critical"
          : nextState.mode === "normal"
            ? "info"
            : "warning",
      action: nextState.mode === "normal" ? "observe" : "contain",
      reason:
        requestedReason ||
        (nextState.mode === "normal"
          ? "containment_cleared"
          : "containment_updated"),
      previousState: currentState,
      nextState,
      message:
        nextState.mode === "normal"
          ? "Containment state returned to normal."
          : "Containment state updated."
    });
  }

  return {
    ok,
    state: nextState
  };
}

export async function clearContainmentState() {
  const previousState = await getContainmentState();
  const clearedState = createDefaultContainmentState();
  const ok = await storeContainmentState(clearedState);

  if (ok && !statesAreEquivalent(previousState, clearedState)) {
    await recordContainmentEvent({
      type: "containment_cleared",
      severity: "info",
      action: "observe",
      reason: "manual_clear",
      previousState,
      nextState: clearedState,
      message: "Containment state was cleared manually."
    });
  }

  return {
    ok,
    state: clearedState
  };
}

export async function evaluateContainment({
  route = "",
  isAdminRoute = false,
  isWriteAction = false,
  actionType = ""
} = {}) {
  const state = await getContainmentState();
  const normalizedRoute = normalizeRoute(route);
  const normalizedActionType = normalizeActionType(actionType);

  let blocked = false;
  let reason = "";
  let action = "allow";

  if (state.flags.lockdown) {
    blocked = true;
    action = "block";
    reason = "lockdown_active";
  } else if (state.flags.readOnlyMode && isWriteAction) {
    blocked = true;
    action = "block";
    reason = "read_only_mode_active";
  } else if (
    state.flags.freezeRegistrations &&
    normalizedRoute.includes("signup")
  ) {
    blocked = true;
    action = "block";
    reason = "registrations_frozen";
  } else if (
    state.flags.disableProfileEdits &&
    normalizedRoute.includes("profile")
  ) {
    blocked = true;
    action = "block";
    reason = "profile_edits_disabled";
  } else if (
    state.flags.disableUploads &&
    normalizedActionType === "upload"
  ) {
    blocked = true;
    action = "block";
    reason = "uploads_disabled";
  } else if (
    state.flags.lockAdminWrites &&
    isAdminRoute &&
    isWriteAction
  ) {
    blocked = true;
    action = "block";
    reason = "admin_writes_locked";
  } else if (state.flags.forceCaptcha) {
    action = "challenge";
    reason = "force_captcha_enabled";
  }

  return {
    mode: state.mode,
    blocked,
    action,
    reason,
    flags: sanitizeFlags(state.flags),
    expiresAt: safeInt(state.expiresAt, 0, 0, getNowMax()),
    updatedAt: safeInt(state.updatedAt, Date.now(), 0, getNowMax())
  };
}
