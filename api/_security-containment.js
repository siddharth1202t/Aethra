import { redis } from "./_redis.js";

const CONTAINMENT_KEY = "security:containment:global";
const CONTAINMENT_TTL_MS = 24 * 60 * 60 * 1000;

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
  "forceCaptcha"
]);

function safeString(value, maxLength = 200) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeBoolean(value) {
  return value === true;
}

function normalizeMode(mode = "") {
  const normalized = safeString(mode || "normal", 30).toLowerCase();
  return ALLOWED_MODES.has(normalized) ? normalized : "normal";
}

function sanitizeFlags(flags = {}) {
  const output = {};

  for (const key of ALLOWED_FLAGS) {
    output[key] = safeBoolean(flags?.[key]);
  }

  return output;
}

function createDefaultContainmentState() {
  return {
    mode: "normal",
    reason: "",
    updatedAt: Date.now(),
    expiresAt: 0,
    flags: {
      freezeRegistrations: false,
      disableProfileEdits: false,
      lockAdminWrites: false,
      readOnlyMode: false,
      disableUploads: false,
      forceCaptcha: false
    }
  };
}

function normalizeContainmentState(raw) {
  const base = createDefaultContainmentState();
  const state = raw && typeof raw === "object" ? raw : {};

  return {
    mode: normalizeMode(state.mode),
    reason: safeString(state.reason || "", 300),
    updatedAt: safeNumber(state.updatedAt, Date.now()),
    expiresAt: safeNumber(state.expiresAt, 0),
    flags: sanitizeFlags({
      ...base.flags,
      ...(state.flags || {})
    })
  };
}

async function getStoredContainmentState() {
  try {
    const raw = await redis.get(CONTAINMENT_KEY);

    if (!raw) {
      return createDefaultContainmentState();
    }

    if (typeof raw === "string") {
      return normalizeContainmentState(JSON.parse(raw));
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
    const ttlSeconds = Math.max(1, Math.ceil(CONTAINMENT_TTL_MS / 1000));
    await redis.set(CONTAINMENT_KEY, JSON.stringify(state), { ex: ttlSeconds });
    return true;
  } catch (error) {
    console.error("Containment write failed:", error);
    return false;
  }
}

function getDefaultFlagsForMode(mode) {
  if (mode === "lockdown") {
    return {
      freezeRegistrations: true,
      disableProfileEdits: true,
      lockAdminWrites: true,
      readOnlyMode: true,
      disableUploads: true,
      forceCaptcha: true
    };
  }

  if (mode === "elevated") {
    return {
      freezeRegistrations: false,
      disableProfileEdits: false,
      lockAdminWrites: false,
      readOnlyMode: false,
      disableUploads: false,
      forceCaptcha: true
    };
  }

  return createDefaultContainmentState().flags;
}

export async function getContainmentState() {
  const state = await getStoredContainmentState();
  const now = Date.now();

  if (state.expiresAt > 0 && now > state.expiresAt) {
    const reset = createDefaultContainmentState();
    await storeContainmentState(reset);
    return reset;
  }

  return state;
}

export async function setContainmentState({
  mode = "normal",
  reason = "",
  durationMs = 0,
  flags = {}
} = {}) {
  const normalizedMode = normalizeMode(mode);
  const mergedFlags = {
    ...getDefaultFlagsForMode(normalizedMode),
    ...sanitizeFlags(flags)
  };

  const now = Date.now();
  const safeDurationMs = Math.max(0, safeNumber(durationMs, 0));

  const nextState = {
    mode: normalizedMode,
    reason: safeString(reason || "", 300),
    updatedAt: now,
    expiresAt: safeDurationMs > 0 ? now + safeDurationMs : 0,
    flags: mergedFlags
  };

  const ok = await storeContainmentState(nextState);

  return {
    ok,
    state: nextState
  };
}

export async function clearContainmentState() {
  const state = createDefaultContainmentState();
  const ok = await storeContainmentState(state);

  return {
    ok,
    state
  };
}

export async function evaluateContainment({
  route = "",
  isAdminRoute = false,
  isWriteAction = false,
  actionType = ""
} = {}) {
  const state = await getContainmentState();
  const normalizedRoute = safeString(route || "", 200).toLowerCase();
  const normalizedActionType = safeString(actionType || "", 50).toLowerCase();

  let blocked = false;
  let reason = "";
  let action = "allow";

  if (state.flags.readOnlyMode && isWriteAction) {
    blocked = true;
    reason = "read_only_mode_active";
    action = "block";
  }

  if (!blocked && state.flags.freezeRegistrations && normalizedRoute.includes("signup")) {
    blocked = true;
    reason = "registrations_frozen";
    action = "block";
  }

  if (!blocked && state.flags.disableProfileEdits && normalizedRoute.includes("profile")) {
    blocked = true;
    reason = "profile_edits_disabled";
    action = "block";
  }

  if (!blocked && state.flags.disableUploads && normalizedActionType === "upload") {
    blocked = true;
    reason = "uploads_disabled";
    action = "block";
  }

  if (!blocked && state.flags.lockAdminWrites && isAdminRoute && isWriteAction) {
    blocked = true;
    reason = "admin_writes_locked";
    action = "block";
  }

  if (!blocked && state.flags.forceCaptcha) {
    action = "challenge";
    reason = "force_captcha_enabled";
  }

  return {
    mode: state.mode,
    blocked,
    action,
    reason,
    flags: state.flags,
    expiresAt: state.expiresAt,
    updatedAt: state.updatedAt
  };
}
