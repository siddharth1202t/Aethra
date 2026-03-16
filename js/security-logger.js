const ALLOWED_CLIENT_TYPES = new Set([
  "captcha_missing",
  "client_security_event",
  "page_error",
  "suspicious_client_behavior"
]);

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error"
]);

const MAX_METADATA_DEPTH = 4;
const MAX_METADATA_KEYS = 20;
const MAX_ARRAY_ITEMS = 20;
const MAX_MESSAGE_LENGTH = 500;

const CLIENT_LOG_RATE_LIMIT = 20; // logs per minute
const CLIENT_LOG_WINDOW = 60000;

let cachedSessionId = "";
let logCounter = 0;
let logWindowStart = Date.now();

/* ---------------- BASIC SAFE HELPERS ---------------- */

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function safeType(type) {
  const normalized = safeString(type || "client_security_event", 50).toLowerCase();
  return ALLOWED_CLIENT_TYPES.has(normalized)
    ? normalized
    : "client_security_event";
}

function safeLevel(level) {
  const normalized = safeString(level || "warning", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized)
    ? normalized
    : "warning";
}

/* ---------------- METADATA SANITIZATION ---------------- */

function sanitizeMetadata(value, depth = 0) {
  if (depth > MAX_METADATA_DEPTH) {
    return "[max-depth]";
  }

  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value === "string") {
    return safeString(value, 1000);
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) => sanitizeMetadata(item, depth + 1));
  }

  if (isPlainObject(value)) {
    const output = {};
    const entries = Object.entries(value).slice(0, MAX_METADATA_KEYS);

    for (const [key, val] of entries) {
      output[safeString(key, 100)] = sanitizeMetadata(val, depth + 1);
    }

    return output;
  }

  return safeString(value, 500);
}

/* ---------------- CLIENT SNAPSHOT ---------------- */

function buildClientSnapshot() {
  try {
    return {
      userAgent: safeString(navigator?.userAgent || "", 300),
      language: safeString(navigator?.language || "", 40),
      platform: safeString(navigator?.platform || "", 100),
      screenWidth: safeNumber(window?.screen?.width),
      screenHeight: safeNumber(window?.screen?.height),
      url: safeString(window?.location?.href || "", 500),
      referrer: safeString(document?.referrer || "", 500)
    };
  } catch {
    return {};
  }
}

/* ---------------- SESSION MANAGEMENT ---------------- */

function createSessionId() {
  try {
    const array = new Uint32Array(4);
    crypto.getRandomValues(array);
    return Array.from(array, (part) => part.toString(16)).join("-");
  } catch {
    return `session-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  }
}

function getSessionId() {
  if (cachedSessionId) {
    return cachedSessionId;
  }

  try {
    const existing = sessionStorage.getItem("aethra_security_session");

    if (existing) {
      cachedSessionId = safeString(existing, 120);
      return cachedSessionId;
    }

    const created = createSessionId();
    sessionStorage.setItem("aethra_security_session", created);

    cachedSessionId = safeString(created, 120);
    return cachedSessionId;
  } catch {
    cachedSessionId = safeString(createSessionId(), 120);
    return cachedSessionId;
  }
}

/* ---------------- RATE LIMIT ---------------- */

function allowClientLog() {
  const now = Date.now();

  if (now - logWindowStart > CLIENT_LOG_WINDOW) {
    logWindowStart = now;
    logCounter = 0;
  }

  logCounter++;

  if (logCounter > CLIENT_LOG_RATE_LIMIT) {
    return false;
  }

  return true;
}

/* ---------------- ABORT SIGNAL ---------------- */

function createAbortSignal(timeoutMs = 4000) {
  if (typeof AbortController === "undefined") {
    return { signal: undefined, cleanup: () => {} };
  }

  const controller = new AbortController();

  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  return {
    signal: controller.signal,
    cleanup: () => clearTimeout(timeoutId)
  };
}

/* ---------------- MAIN LOGGER ---------------- */

export async function logSecurityEvent(data = {}) {
  try {

    if (!allowClientLog()) {
      return;
    }

    const payload = {
      type: safeType(data.type),
      level: safeLevel(data.level),
      message: safeString(data.message || "", MAX_MESSAGE_LENGTH),
      email: safeString(data.email || "", 200),
      userId: safeString(data.userId || "", 200),
      eventAt: Date.now(),
      sessionId: getSessionId(),
      metadata: sanitizeMetadata(data.metadata || {}),
      client: buildClientSnapshot()
    };

    const { signal, cleanup } = createAbortSignal(4000);

    try {
      await fetch("/api/security-log", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        keepalive: true,
        signal
      });
    } finally {
      cleanup();
    }

  } catch (error) {
    console.warn("Security log failed:", error);
  }
}

/* ---------------- BACKWARD COMPATIBILITY ---------------- */

export const writeSecurityLog = logSecurityEvent;
