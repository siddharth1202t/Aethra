import { getRedis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const CONTAINMENT_KEY = "security:containment:global";
const ACTOR_CONTAINMENT_PREFIX = "security:containment:actor";
const CONTAINMENT_TTL_MS = 24 * 60 * 60 * 1000;
const CONTAINMENT_TTL_SECONDS = Math.max(
  1,
  Math.ceil(CONTAINMENT_TTL_MS / 1000)
);
const MAX_FUTURE_TIME_MS = 7 * 24 * 60 * 60 * 1000;

const ALLOWED_MODES = new Set([
  "normal",
  "elevated",
  "defense",
  "lockdown"
]);

const ALLOWED_FLAGS = new Set([
  "freezeRegistrations",
  "disableProfileEdits",
  "lockAdminWrites",
  "readOnlyMode",
  "disableUploads",
  "forceCaptcha",
  "lockdown",
  "lockAccount",
  "killSessions",
  "blockActor"
]);

const MODE_RANK = {
  normal: 0,
  elevated: 1,
  defense: 2,
  lockdown: 3
};

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

/* -------------------- NORMALIZATION -------------------- */

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

function normalizeActorType(value = "") {
  return safeString(value || "actor", 40)
    .replace(/[^a-zA-Z0-9:_-]/g, "_")
    .toLowerCase();
}

function normalizeActorId(value = "") {
  return safeString(value || "", 160).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function buildActorContainmentKey(actorType = "actor", actorId = "") {
  return `${ACTOR_CONTAINMENT_PREFIX}:${normalizeActorType(actorType)}:${normalizeActorId(actorId)}`;
}

function createDefaultFlags() {
  return {
    freezeRegistrations: false,
    disableProfileEdits: false,
    lockAdminWrites: false,
    readOnlyMode: false,
    disableUploads: false,
    forceCaptcha: false,
    lockdown: false,
    lockAccount: false,
    killSessions: false,
    blockActor: false
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
      lockdown: true,
      lockAccount: false,
      killSessions: false,
      blockActor: false
    };
  }

  if (normalizedMode === "defense") {
    return {
      freezeRegistrations: false,
      disableProfileEdits: false,
      lockAdminWrites: false,
      readOnlyMode: false,
      disableUploads: false,
      forceCaptcha: true,
      lockdown: false,
      lockAccount: false,
      killSessions: false,
      blockActor: false
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
      lockdown: false,
      lockAccount: false,
      killSessions: false,
      blockActor: false
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

function createDefaultActorContainmentState(actorType = "actor", actorId = "") {
  return {
    actorType: normalizeActorType(actorType),
    actorId: normalizeActorId(actorId),
    reason: "",
    updatedAt: Date.now(),
    expiresAt: 0,
    killSessionsIssuedAt: 0,
    containmentVersion: 0,
    flags: {
      ...createDefaultFlags(),
      lockAccount: false,
      killSessions: false,
      blockActor: false
    }
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

function normalizeActorContainmentState(raw, actorType = "actor", actorId = "") {
  const base = createDefaultActorContainmentState(actorType, actorId);
  const state = raw && typeof raw === "object" ? raw : {};
  const nowMax = getNowMax();

  const flags = sanitizeFlags({
    ...base.flags,
    ...(state.flags || {})
  });

  return {
    actorType: normalizeActorType(state.actorType || base.actorType),
    actorId: normalizeActorId(state.actorId || base.actorId),
    reason: safeString(state.reason || "", 300),
    updatedAt: safeInt(state.updatedAt, base.updatedAt, 0, nowMax),
    expiresAt: safeInt(state.expiresAt, 0, 0, nowMax),
    killSessionsIssuedAt: safeInt(state.killSessionsIssuedAt, 0, 0, nowMax),
    containmentVersion: safeInt(state.containmentVersion, 0, 0, 1_000_000),
    flags
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

function actorStatesAreEquivalent(a = {}, b = {}) {
  const left = normalizeActorContainmentState(a, a?.actorType || "actor", a?.actorId || "");
  const right = normalizeActorContainmentState(b, b?.actorType || "actor", b?.actorId || "");

  if (left.actorType !== right.actorType) return false;
  if (left.actorId !== right.actorId) return false;
  if (left.reason !== right.reason) return false;
  if (left.expiresAt !== right.expiresAt) return false;
  if (left.killSessionsIssuedAt !== right.killSessionsIssuedAt) return false;
  if (left.containmentVersion !== right.containmentVersion) return false;

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
    lockdown: normalized.flags.lockdown,
    lockAccount: normalized.flags.lockAccount,
    killSessions: normalized.flags.killSessions,
    blockActor: normalized.flags.blockActor
  };
}

function buildActorContainmentMetadata(state = {}) {
  const normalized = normalizeActorContainmentState(
    state,
    state?.actorType || "actor",
    state?.actorId || ""
  );

  return {
    actorType: normalized.actorType,
    actorId: normalized.actorId,
    expiresAt: normalized.expiresAt,
    killSessionsIssuedAt: normalized.killSessionsIssuedAt,
    containmentVersion: normalized.containmentVersion,
    lockAccount: normalized.flags.lockAccount,
    killSessions: normalized.flags.killSessions,
    blockActor: normalized.flags.blockActor,
    forceCaptcha: normalized.flags.forceCaptcha
  };
}

async function recordContainmentEvent({
  env = {},
  type,
  severity,
  action,
  reason,
  previousState,
  nextState,
  message,
  metadata = {}
}) {
  try {
    await appendSecurityEvent(env, {
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
        ...buildContainmentMetadata(nextState),
        ...(metadata || {})
      }
    });
  } catch (error) {
    console.error("Containment event write failed:", error);
  }
}

async function recordActorContainmentEvent({
  env = {},
  type,
  severity,
  action,
  reason,
  previousState,
  nextState,
  message,
  metadata = {}
}) {
  try {
    await appendSecurityEvent(env, {
      type: safeString(type || "actor_containment_updated", 60),
      severity: safeString(severity || "warning", 20).toLowerCase(),
      action: safeString(action || "contain", 30).toLowerCase(),
      mode:
        nextState?.flags?.blockActor === true
          ? "lockdown"
          : nextState?.flags?.forceCaptcha === true
            ? "defense"
            : "elevated",
      reason: safeString(reason || "", 300),
      message: safeString(message || "", 500),
      metadata: {
        previousExpiresAt: safeInt(previousState?.expiresAt, 0, 0, getNowMax()),
        nextExpiresAt: safeInt(nextState?.expiresAt, 0, 0, getNowMax()),
        ...buildActorContainmentMetadata(nextState),
        ...(metadata || {})
      }
    });
  } catch (error) {
    console.error("Actor containment event write failed:", error);
  }
}

async function getStoredContainmentState(env = {}) {
  const redis = getRedis(env);

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

async function storeContainmentState(env = {}, state) {
  const redis = getRedis(env);

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

async function getStoredActorContainmentState(env = {}, actorType = "actor", actorId = "") {
  const redis = getRedis(env);
  const safeActorType = normalizeActorType(actorType);
  const safeActorId = normalizeActorId(actorId);

  if (!safeActorId) {
    return createDefaultActorContainmentState(safeActorType, safeActorId);
  }

  try {
    const raw = await redis.get(buildActorContainmentKey(safeActorType, safeActorId));

    if (!raw) {
      return createDefaultActorContainmentState(safeActorType, safeActorId);
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      return normalizeActorContainmentState(parsed, safeActorType, safeActorId);
    }

    if (typeof raw === "object") {
      return normalizeActorContainmentState(raw, safeActorType, safeActorId);
    }

    return createDefaultActorContainmentState(safeActorType, safeActorId);
  } catch (error) {
    console.error("Actor containment read failed:", error);
    return createDefaultActorContainmentState(safeActorType, safeActorId);
  }
}

async function storeActorContainmentState(env = {}, state) {
  const redis = getRedis(env);
  const normalized = normalizeActorContainmentState(
    state,
    state?.actorType || "actor",
    state?.actorId || ""
  );

  if (!normalized.actorId) return false;

  try {
    await redis.set(
      buildActorContainmentKey(normalized.actorType, normalized.actorId),
      JSON.stringify(normalized),
      { ex: CONTAINMENT_TTL_SECONDS }
    );
    return true;
  } catch (error) {
    console.error("Actor containment write failed:", error);
    return false;
  }
}

function deriveEffectiveContainmentMode(globalState, actorState) {
  let mode = normalizeMode(globalState?.mode || "normal");

  if (actorState?.flags?.blockActor === true) {
    mode = getStrongerMode(mode, "lockdown");
  } else if (
    actorState?.flags?.lockAccount === true ||
    actorState?.flags?.killSessions === true
  ) {
    mode = getStrongerMode(mode, "defense");
  } else if (actorState?.flags?.forceCaptcha === true) {
    mode = getStrongerMode(mode, "elevated");
  }

  return mode;
}

function buildEnforcementSummary({
  mergedFlags = {},
  route = "",
  isAdminRoute = false,
  isWriteAction = false,
  actionType = "",
  actorState = null,
  globalState = null
}) {
  const normalizedRoute = normalizeRoute(route);
  const normalizedActionType = normalizeActionType(actionType);

  let blocked = false;
  let reason = "";
  let action = "allow";
  let mustDenyWrite = false;
  let requiresStepUp = false;

  if (mergedFlags.lockdown || mergedFlags.blockActor) {
    blocked = true;
    action = "block";
    reason = mergedFlags.blockActor ? "actor_blocked" : "lockdown_active";
  } else if (mergedFlags.lockAccount) {
    blocked = true;
    action = "block";
    reason = "account_locked";
  } else if (mergedFlags.readOnlyMode && isWriteAction) {
    blocked = true;
    action = "block";
    reason = "read_only_mode_active";
    mustDenyWrite = true;
  } else if (mergedFlags.freezeRegistrations && normalizedRoute.includes("signup")) {
    blocked = true;
    action = "block";
    reason = "registrations_frozen";
  } else if (mergedFlags.disableProfileEdits && normalizedRoute.includes("profile")) {
    blocked = true;
    action = "block";
    reason = "profile_edits_disabled";
    mustDenyWrite = true;
  } else if (mergedFlags.disableUploads && normalizedActionType === "upload") {
    blocked = true;
    action = "block";
    reason = "uploads_disabled";
    mustDenyWrite = true;
  } else if (mergedFlags.lockAdminWrites && isAdminRoute && isWriteAction) {
    blocked = true;
    action = "block";
    reason = "admin_writes_locked";
    mustDenyWrite = true;
  } else if (mergedFlags.forceCaptcha) {
    action = "challenge";
    reason = "force_captcha_enabled";
    requiresStepUp = true;
  }

  return {
    blocked,
    action,
    reason,
    mustDenyWrite,
    requiresStepUp,
    mustBlock: blocked,
    mustLockAccount: mergedFlags.lockAccount === true,
    mustKillSessions: mergedFlags.killSessions === true,
    mustBlockActor: mergedFlags.blockActor === true,
    effectiveMode: deriveEffectiveContainmentMode(globalState, actorState),
    killSessionsIssuedAt: safeInt(actorState?.killSessionsIssuedAt, 0, 0, getNowMax()),
    containmentVersion: safeInt(actorState?.containmentVersion, 0, 0, 1_000_000)
  };
}

/* -------------------- PUBLIC API -------------------- */

export async function getContainmentState(env = {}) {
  const state = await getStoredContainmentState(env);

  if (!isContainmentExpired(state)) {
    return normalizeContainmentState(state);
  }

  const previousState = normalizeContainmentState(state);
  const resetState = createDefaultContainmentState();

  await storeContainmentState(env, resetState);

  await recordContainmentEvent({
    env,
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

export async function setContainmentState(
  env = {},
  {
    mode = "normal",
    reason = "",
    durationMs = 0,
    flags = {},
    allowDowngrade = false
  } = {}
) {
  const requestedMode = normalizeMode(mode);
  const requestedReason = safeString(reason || "", 300);
  const requestedDurationMs = Math.max(0, safeNumber(durationMs, 0));
  const requestedFlags = sanitizeFlags(flags);
  const now = Date.now();

  const currentState = await getContainmentState(env);

  let finalMode = requestedMode;
  let finalFlags = {
    ...getDefaultFlagsForMode(requestedMode),
    ...requestedFlags
  };

  if (!allowDowngrade) {
    const strongerMode = getStrongerMode(currentState.mode, requestedMode);

    if (strongerMode !== requestedMode) {
      finalMode = strongerMode;
      finalFlags = mergeFlagsForEscalation(currentState.flags, finalFlags);
    } else if (strongerMode === currentState.mode && strongerMode === requestedMode) {
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

  const ok = await storeContainmentState(env, nextState);

  if (ok && !statesAreEquivalent(currentState, nextState)) {
    await recordContainmentEvent({
      env,
      type: nextState.mode === "normal" ? "containment_cleared" : "containment_updated",
      severity:
        nextState.mode === "lockdown"
          ? "critical"
          : nextState.mode === "defense"
            ? "error"
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

export async function setActorContainment(
  env = {},
  {
    actorType = "actor",
    actorId = "",
    reason = "",
    durationMs = 15 * 60 * 1000,
    flags = {}
  } = {}
) {
  const safeActorType = normalizeActorType(actorType);
  const safeActorId = normalizeActorId(actorId);

  if (!safeActorId) {
    return { ok: false, code: "missing_actor_id" };
  }

  const now = Date.now();
  const currentState = await getStoredActorContainmentState(env, safeActorType, safeActorId);
  const requestedFlags = sanitizeFlags(flags);

  const nextState = normalizeActorContainmentState(
    {
      actorType: safeActorType,
      actorId: safeActorId,
      reason: safeString(reason || "actor_containment", 300),
      updatedAt: now,
      expiresAt: durationMs > 0 ? now + Math.max(0, safeNumber(durationMs, 0)) : 0,
      killSessionsIssuedAt:
        requestedFlags.killSessions === true
          ? now
          : safeInt(currentState.killSessionsIssuedAt, 0, 0, getNowMax()),
      containmentVersion: safeInt(currentState.containmentVersion, 0, 0, 1_000_000) + 1,
      flags: sanitizeFlags({
        ...currentState.flags,
        ...requestedFlags
      })
    },
    safeActorType,
    safeActorId
  );

  const ok = await storeActorContainmentState(env, nextState);

  if (ok && !actorStatesAreEquivalent(currentState, nextState)) {
    await recordActorContainmentEvent({
      env,
      type: "actor_containment_updated",
      severity:
        nextState.flags.lockAccount || nextState.flags.killSessions || nextState.flags.blockActor
          ? "critical"
          : nextState.flags.forceCaptcha
            ? "warning"
            : "info",
      action: "contain",
      reason: nextState.reason,
      previousState: currentState,
      nextState,
      message: "Actor-specific containment state updated.",
      metadata: {
        actorContainment: true
      }
    });
  }

  return {
    ok,
    state: nextState
  };
}

export async function clearActorContainment(
  env = {},
  {
    actorType = "actor",
    actorId = "",
    reason = "manual_actor_clear"
  } = {}
) {
  const safeActorType = normalizeActorType(actorType);
  const safeActorId = normalizeActorId(actorId);

  if (!safeActorId) {
    return { ok: false, code: "missing_actor_id" };
  }

  const previousState = await getStoredActorContainmentState(env, safeActorType, safeActorId);
  const clearedState = createDefaultActorContainmentState(safeActorType, safeActorId);
  const ok = await storeActorContainmentState(env, clearedState);

  if (ok && !actorStatesAreEquivalent(previousState, clearedState)) {
    await recordActorContainmentEvent({
      env,
      type: "actor_containment_cleared",
      severity: "info",
      action: "observe",
      reason: safeString(reason, 300),
      previousState,
      nextState: clearedState,
      message: "Actor-specific containment state was cleared."
    });
  }

  return {
    ok,
    state: clearedState
  };
}

export async function getActorContainment(
  env = {},
  {
    actorType = "actor",
    actorId = ""
  } = {}
) {
  const state = await getStoredActorContainmentState(env, actorType, actorId);

  if (!isContainmentExpired(state)) {
    return state;
  }

  const previousState = normalizeActorContainmentState(state, actorType, actorId);
  const resetState = createDefaultActorContainmentState(actorType, actorId);

  await storeActorContainmentState(env, resetState);

  await recordActorContainmentEvent({
    env,
    type: "actor_containment_expired_reset",
    severity: "info",
    action: "observe",
    reason: "actor_containment_expired",
    previousState,
    nextState: resetState,
    message: "Actor containment state expired and was reset."
  });

  return resetState;
}

export async function clearContainmentState(env = {}) {
  const previousState = await getContainmentState(env);
  const clearedState = createDefaultContainmentState();
  const ok = await storeContainmentState(env, clearedState);

  if (ok && !statesAreEquivalent(previousState, clearedState)) {
    await recordContainmentEvent({
      env,
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

export async function evaluateContainment(
  env = {},
  {
    route = "",
    isAdminRoute = false,
    isWriteAction = false,
    actionType = "",
    actorType = "",
    actorId = ""
  } = {}
) {
  const globalState = await getContainmentState(env);
  const actorState =
    actorId ? await getActorContainment(env, { actorType, actorId }) : null;

  const mergedFlags = sanitizeFlags({
    ...(globalState?.flags || {}),
    ...(actorState?.flags || {})
  });

  const enforcement = buildEnforcementSummary({
    mergedFlags,
    route,
    isAdminRoute,
    isWriteAction,
    actionType,
    actorState,
    globalState
  });

  return {
    mode: enforcement.effectiveMode,
    blocked: enforcement.blocked,
    action: enforcement.action,
    reason: enforcement.reason,
    flags: mergedFlags,
    expiresAt: Math.max(
      safeInt(globalState?.expiresAt, 0, 0, getNowMax()),
      safeInt(actorState?.expiresAt, 0, 0, getNowMax())
    ),
    updatedAt: Math.max(
      safeInt(globalState?.updatedAt, Date.now(), 0, getNowMax()),
      safeInt(actorState?.updatedAt, 0, 0, getNowMax())
    ),
    criticalAttack:
      mergedFlags.lockdown === true ||
      mergedFlags.blockActor === true ||
      mergedFlags.lockAccount === true ||
      mergedFlags.killSessions === true,
    enforcement,
    actorContainment: actorState
      ? {
          actorType: actorState.actorType,
          actorId: actorState.actorId,
          expiresAt: safeInt(actorState.expiresAt, 0, 0, getNowMax()),
          killSessions: safeBoolean(actorState.flags?.killSessions),
          killSessionsIssuedAt: safeInt(actorState.killSessionsIssuedAt, 0, 0, getNowMax()),
          lockAccount: safeBoolean(actorState.flags?.lockAccount),
          blockActor: safeBoolean(actorState.flags?.blockActor),
          containmentVersion: safeInt(actorState.containmentVersion, 0, 0, 1_000_000)
        }
      : null
  };
}
