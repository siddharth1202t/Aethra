import { redis } from "./_redis.js";

const SECURITY_EVENTS_KEY = "security:events:recent";
const SECURITY_EVENTS_MAX_ITEMS = 100;
const SECURITY_EVENTS_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SECURITY_EVENTS_TTL_SECONDS = Math.max(
  1,
  Math.ceil(SECURITY_EVENTS_TTL_MS / 1000)
);

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
    .replace(/[^a-zA-Z0-9/_-]/g, "")
    .toLowerCase()
    .slice(0, 200);
}

function normalizeIp(value = "") {
  return safeString(value || "", 100);
}

function normalizeEventType(value = "") {
  return safeString(value || "security_event", 80)
    .toLowerCase()
    .replace(/[^a-z0-9_:-]/g, "_");
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

    if (
      rawValue === null ||
      typeof rawValue === "string" ||
      typeof rawValue === "number" ||
      typeof rawValue === "boolean"
    ) {
      output[key] =
        typeof rawValue === "string" ? safeString(rawValue, 300) : rawValue;
      continue;
    }

    if (Array.isArray(rawValue)) {
      output[key] = rawValue
        .slice(0, 10)
        .map((item) => {
          if (
            item === null ||
            typeof item === "string" ||
            typeof item === "number" ||
            typeof item === "boolean"
          ) {
            return typeof item === "string" ? safeString(item, 120) : item;
          }
          return "[complex]";
        });
      continue;
    }

    output[key] = "[complex]";
  }

  return output;
}

function createEventId() {
  return `evt_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeStoredEvent(raw) {
  const event = raw && typeof raw === "object" ? raw : {};

  return {
    id: safeString(event.id || createEventId(), 50),
    timestamp: safeInt(event.timestamp, Date.now(), 0, Date.now() + 60_000),
    type: normalizeEventType(event.type || "security_event"),
    severity: normalizeSeverity(event.severity || "info"),
    action: normalizeAction(event.action || "observe"),
    route: normalizeRoute(event.route || ""),
    ip: normalizeIp(event.ip || ""),
    sessionId: safeString(event.sessionId || "", 120),
    userId: safeString(event.userId || "", 120),
    mode: safeString(event.mode || "", 30).toLowerCase(),
    reason: safeString(event.reason || "", 300),
    message: safeString(event.message || "", 500),
    metadata: sanitizeMetadata(event.metadata || {})
  };
}

async function getStoredEvents() {
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

async function storeEvents(events = []) {
  try {
    const normalizedEvents = Array.isArray(events)
      ? events.map(normalizeStoredEvent).slice(0, SECURITY_EVENTS_MAX_ITEMS)
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

export async function appendSecurityEvent({
  type = "security_event",
  severity = "info",
  action = "observe",
  route = "",
  ip = "",
  sessionId = "",
  userId = "",
  mode = "",
  reason = "",
  message = "",
  metadata = {}
} = {}) {
  const event = normalizeStoredEvent({
    id: createEventId(),
    timestamp: Date.now(),
    type,
    severity,
    action,
    route,
    ip,
    sessionId,
    userId,
    mode,
    reason,
    message,
    metadata
  });

  const currentEvents = await getStoredEvents();
  const nextEvents = [event, ...currentEvents].slice(0, SECURITY_EVENTS_MAX_ITEMS);
  const ok = await storeEvents(nextEvents);

  return {
    ok,
    event
  };
}

export async function getRecentSecurityEvents({
  limit = 50,
  severity = "",
  action = "",
  type = ""
} = {}) {
  const safeLimit = safeInt(limit, 50, 1, SECURITY_EVENTS_MAX_ITEMS);
  const normalizedSeverity = severity ? normalizeSeverity(severity) : "";
  const normalizedAction = action ? normalizeAction(action) : "";
  const normalizedType = type ? normalizeEventType(type) : "";

  const events = await getStoredEvents();

  const filtered = events.filter((event) => {
    if (normalizedSeverity && event.severity !== normalizedSeverity) {
      return false;
    }

    if (normalizedAction && event.action !== normalizedAction) {
      return false;
    }

    if (normalizedType && event.type !== normalizedType) {
      return false;
    }

    return true;
  });

  return filtered.slice(0, safeLimit);
}

export async function clearSecurityEvents() {
  const ok = await storeEvents([]);

  return {
    ok,
    cleared: true
  };
}
