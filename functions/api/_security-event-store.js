import { getRedis } from "./_redis.js";

const SECURITY_EVENTS_KEY = "security:events:recent";
const SECURITY_EVENTS_MAX_ITEMS = 100;
const SECURITY_EVENTS_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SECURITY_EVENTS_TTL_SECONDS = Math.max(
  1,
  Math.ceil(SECURITY_EVENTS_TTL_MS / 1000)
);
const MAX_FUTURE_EVENT_MS = 60 * 1000;

const ALLOWED_SEVERITIES = new Set([
  "info",
  "warning",
  "error",
  "critical"
]);

const ALLOWED_ACTIONS = new Set([
  "allow",
  "challenge",
  "throttle",
  "block",
  "contain",
  "observe"
]);

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

function normalizeSeverity(value = "info") {
  const normalized = safeString(value || "info", 20).toLowerCase();
  return ALLOWED_SEVERITIES.has(normalized) ? normalized : "info";
}

function normalizeAction(value = "observe") {
  const normalized = safeString(value || "observe", 20).toLowerCase();
  return ALLOWED_ACTIONS.has(normalized) ? normalized : "observe";
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

function normalizeIp(value = "") {
  let ip = safeString(value || "", 100);

  if (!ip) return "";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return ip;
}

function normalizeEventType(value = "") {
  return safeString(value || "security_event", 80)
    .toLowerCase()
    .replace(/[^a-z0-9_:-]/g, "_");
}

function sanitizeMetadataValue(value, depth = 0) {
  if (depth > 2) {
    return "[complex]";
  }

  if (
    value === null ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "string") {
    return safeString(value, 300);
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, 10)
      .map((item) => sanitizeMetadataValue(item, depth + 1));
  }

  if (value && typeof value === "object") {
    const output = {};
    const entries = Object.entries(value).slice(0, 10);

    for (const [rawKey, rawValue] of entries) {
      const key = safeString(rawKey, 50).replace(/[^a-zA-Z0-9_:-]/g, "_");
      if (!key) continue;
      output[key] = sanitizeMetadataValue(rawValue, depth + 1);
    }

    return output;
  }

  return safeString(value, 120);
}

function sanitizeMetadata(metadata = {}) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return {};
  }

  const output = {};
  const entries = Object.entries(metadata).slice(0, 20);

  for (const [rawKey, rawValue] of entries) {
    const key = safeString(rawKey, 50).replace(/[^a-zA-Z0-9_:-]/g, "_");
    if (!key) continue;
    output[key] = sanitizeMetadataValue(rawValue, 0);
  }

  return output;
}

function createEventId() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);

  const randomHex = Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return `evt_${Date.now()}_${randomHex}`;
}

function normalizeStoredEvent(raw) {
  const event = raw && typeof raw === "object" ? raw : {};
  const maxTimestamp = Date.now() + MAX_FUTURE_EVENT_MS;

  return {
    id: safeString(event.id || createEventId(), 50),
    timestamp: safeInt(event.timestamp, Date.now(), 0, maxTimestamp),
    type: normalizeEventType(event.type || "security_event"),
    severity: normalizeSeverity(event.severity || "info"),
    action: normalizeAction(event.action || "observe"),
    route: normalizeRoute(event.route || ""),
    ip: normalizeIp(event.ip || ""),
    sessionId: safeString(event.sessionId || "", 120),
    userId: safeString(event.userId || "", 120),
    actorKey: safeString(event.actorKey || "", 240),
    requestId: safeString(event.requestId || "", 120),
    mode: safeString(event.mode || "", 30).toLowerCase(),
    reason: safeString(event.reason || "", 300),
    message: safeString(event.message || "", 500),
    metadata: sanitizeMetadata(event.metadata || {})
  };
}

async function getStoredEvents(env = {}) {
  const redis = getRedis(env);

  try {
    const raw = await redis.get(SECURITY_EVENTS_KEY);

    if (!raw) {
      return [];
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, []);
      return Array.isArray(parsed)
        ? parsed.map(normalizeStoredEvent)
        : [];
    }

    if (Array.isArray(raw)) {
      return raw.map(normalizeStoredEvent);
    }

    return [];
  } catch (error) {
    console.error("Security events read failed:", error);
    return [];
  }
}

function sortEventsNewestFirst(events = []) {
  return [...events].sort(
    (a, b) => safeInt(b?.timestamp, 0) - safeInt(a?.timestamp, 0)
  );
}

async function storeEvents(env = {}, events = []) {
  const redis = getRedis(env);

  try {
    const normalizedEvents = Array.isArray(events)
      ? sortEventsNewestFirst(events.map(normalizeStoredEvent)).slice(
          0,
          SECURITY_EVENTS_MAX_ITEMS
        )
      : [];

    await redis.set(SECURITY_EVENTS_KEY, JSON.stringify(normalizedEvents), {
      ex: SECURITY_EVENTS_TTL_SECONDS
    });

    return true;
  } catch (error) {
    console.error("Security events write failed:", error);
    return false;
  }
}

function extractAppendArgs(arg1, arg2) {
  // supports both:
  // appendSecurityEvent(env, event)
  // appendSecurityEvent(event)
  if (arg2 !== undefined) {
    return {
      env: arg1 && typeof arg1 === "object" ? arg1 : {},
      event: arg2 && typeof arg2 === "object" ? arg2 : {}
    };
  }

  return {
    env: {},
    event: arg1 && typeof arg1 === "object" ? arg1 : {}
  };
}

export async function appendSecurityEvent(arg1 = {}, arg2 = undefined) {
  const { env, event: rawEvent } = extractAppendArgs(arg1, arg2);

  const event = normalizeStoredEvent({
    id: createEventId(),
    timestamp: Date.now(),
    type: rawEvent.type,
    severity: rawEvent.severity,
    action: rawEvent.action,
    route: rawEvent.route,
    ip: rawEvent.ip,
    sessionId: rawEvent.sessionId,
    userId: rawEvent.userId,
    actorKey: rawEvent.actorKey,
    requestId: rawEvent.requestId,
    mode: rawEvent.mode,
    reason: rawEvent.reason,
    message: rawEvent.message,
    metadata: rawEvent.metadata
  });

  const currentEvents = await getStoredEvents(env);
  const nextEvents = [event, ...currentEvents];
  const ok = await storeEvents(env, nextEvents);

  return {
    ok,
    event
  };
}

export async function getRecentSecurityEvents(envOrOptions = {}, maybeOptions = undefined) {
  let env = {};
  let options = {};

  if (maybeOptions !== undefined) {
    env = envOrOptions && typeof envOrOptions === "object" ? envOrOptions : {};
    options = maybeOptions && typeof maybeOptions === "object" ? maybeOptions : {};
  } else {
    options = envOrOptions && typeof envOrOptions === "object" ? envOrOptions : {};
  }

  const safeLimit = safeInt(options.limit, 50, 1, SECURITY_EVENTS_MAX_ITEMS);
  const normalizedSeverity = options.severity ? normalizeSeverity(options.severity) : "";
  const normalizedAction = options.action ? normalizeAction(options.action) : "";
  const normalizedType = options.type ? normalizeEventType(options.type) : "";
  const normalizedUserId = options.userId ? safeString(options.userId, 120) : "";
  const normalizedActorKey = options.actorKey ? safeString(options.actorKey, 240) : "";

  const events = sortEventsNewestFirst(await getStoredEvents(env));

  const filtered = events.filter((event) => {
    if (normalizedSeverity && event.severity !== normalizedSeverity) return false;
    if (normalizedAction && event.action !== normalizedAction) return false;
    if (normalizedType && event.type !== normalizedType) return false;
    if (normalizedUserId && event.userId !== normalizedUserId) return false;
    if (normalizedActorKey && event.actorKey !== normalizedActorKey) return false;
    return true;
  });

  return filtered.slice(0, safeLimit);
}

export async function clearSecurityEvents(env = {}) {
  const ok = await storeEvents(env, []);

  return {
    ok,
    cleared: true
  };
}
