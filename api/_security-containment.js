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
  "forceCaptcha",
  "lockdown"
]);

const MODE_RANK = {
  normal: 0,
  elevated: 1,
  lockdown: 2
};

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

function safeInt(value, fallback = 0, min = 0, max = Date.now() + 7 * 24 * 60 * 60 * 1000) {
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
    .replace(/[^a-zA-Z0-9/_-]/g, "")
    .toLowerCase()
    .slice(0, 200);
}

function normalizeActionType(value = "") {
  return safeString(value || "", 50).toLowerCase();
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
      forceCaptcha: false,
      lockdown: false
    }
  };
}

function normalizeContainmentState(raw) {
  const base = createDefaultContainmentState();
  const nowMax = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const state = raw && typeof raw === "object" ? raw : {};

  const normalizedMode = normalizeMode(state.mode || base.mode);
  const mergedFlags = sanitizeFlags({
    ...base.flags,
    ...(state.flags || {})
  });

  // Force consistency between mode and flags
  if (normalizedMode === "lockdown") {
    mergedFlags.lockdown = true;
  }

  if (normalizedMode === "normal") {
    return createDefaultContainmentState();
  }

  return {
    mode: normalizedMode,
    reason: safeString(state.reason || "", 300),
    updatedAt: safeInt(state.updatedAt, Date.now(), 0, nowMax),
    expiresAt: safeInt(state.expiresAt, 0, 0, nowMax),
    flags: mergedFlags
  };
}

async function getStoredContainmentState() {
  try {
    const raw = await redis.get(CONTAINMENT_KEY);

    if (!raw) {
      return createDefaultContainmentState();
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      if (!parsed || typeof parsed !== "object") {
        return createDefaultContainmentState();
      }
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
    const ttlSeconds = Math.max(1, Math.ceil(CONTAINMENT_TTL_MS / 1000));
    const normalized = normalizeContainmentState(state);
    await redis.set(CONTAINMENT_KEY, JSON.stringify(normalized), { ex: ttlSeconds });
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
      forceCaptcha: true,
      lockdown: true
    };
  }

  if (mode === "elevated") {
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

  return createDefaultContainmentState().flags;
}

function getStrongerMode(a = "normal", b = "normal") {
  return MODE_RANK[normalizeMode(a)] >= MODE_RANK[normalizeMode(b)]
    ? normalizeMode(a)
    : normalizeMode(b);
}

function mergeFlagsForEscalation(currentFlags = {}, nextFlags = {}) {
  const output = {};
  for (const key of ALLOWED_FLAGS) {
    output[key] = safeBoolean(currentFlags?.[key]) || safeBoolean(nextFlags?.[key]);
  }
  return output;
}

export async function getContainmentState() {
  const state = await getStoredContainmentState();
  const now = Date.now();

  if (state.expiresAt > 0 && now > state.expiresAt) {
    const reset = createDefaultContainmentState();
    await storeContainmentState(reset);
    return reset;
  }

  return normalizeContainmentState(state);
}

export async function setContainmentState({
  mode = "normal",
  reason = "",
  durationMs = 0,
  flags = {},
  allowDowngrade = false
} = {}) {
  const normalizedMode = normalizeMode(mode);
  const normalizedReason = safeString(reason || "", 300);
  const now = Date.now();
  const safeDurationMs = Math.max(0, safeNumber(durationMs, 0));

  const currentState = await getContainmentState();

  let finalMode = normalizedMode;
  let finalFlags = {
    ...getDefaultFlagsForMode(normalizedMode),
    ...sanitizeFlags(flags)
  };

  if (!allowDowngrade) {
    const strongerMode = getStrongerMode(currentState.mode, normalizedMode);

    if (strongerMode !== normalizedMode) {
      finalMode = strongerMode;
      finalFlags = mergeFlagsForEscalation(
        currentState.flags,
        {
          ...getDefaultFlagsForMode(normalizedMode),
          ...sanitizeFlags(flags)
        }
      );
    } else if (strongerMode === currentState.mode && strongerMode === normalizedMode) {
      finalFlags = mergeFlagsForEscalation(
        currentState.flags,
        finalFlags
      );
    }
  }

  if (finalMode === "normal") {
    finalFlags = createDefaultContainmentState().flags;
  }

  if (finalMode === "lockdown") {
    finalFlags = {
      ...getDefaultFlagsForMode("lockdown"),
      ...mergeFlagsForEscalation(getDefaultFlagsForMode("lockdown"), finalFlags),
      lockdown: true
    };
  }

  const nextState = {
    mode: finalMode,
    reason: normalizedReason,
    updatedAt: now,
    expiresAt: safeDurationMs > 0 ? now + safeDurationMs : 0,
    flags: sanitizeFlags(finalFlags)
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
  const normalizedRoute = normalizeRoute(route || "");
  const normalizedActionType = normalizeActionType(actionType || "");

  let blocked = false;
  let reason = "";
  let action = "allow";

  if (state.flags.lockdown) {
    action = "block";
    blocked = true;
    reason = "lockdown_active";
  }

  if (!blocked && state.flags.readOnlyMode && isWriteAction) {
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
