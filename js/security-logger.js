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
const MAX_EMAIL_LENGTH = 200;
const MAX_USER_ID_LENGTH = 200;
const MAX_URL_LENGTH = 300;
const MAX_REFERRER_LENGTH = 300;

const CLIENT_LOG_RATE_LIMIT = 20; // logs per minute
const CLIENT_LOG_WINDOW = 60_000;
const DEDUPE_WINDOW_MS = 8_000;
const REQUEST_TIMEOUT_MS = 4000;

let cachedSessionId = "";
let logCounter = 0;
let logWindowStart = Date.now();

const recentEventMap = new Map();

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

function safeEmail(email) {
  return safeString(email || "", MAX_EMAIL_LENGTH).trim().toLowerCase();
}

function safeUserId(userId) {
  return safeString(userId || "", MAX_USER_ID_LENGTH).trim();
}

function isValidEmailLike(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ""));
}

function redactUrl(rawUrl, maxLength = MAX_URL_LENGTH) {
  const input = safeString(rawUrl || "", 1000).trim();

  if (!input) {
    return "";
  }

  try {
    const url = new URL(input);
    url.search = "";
    url.hash = "";
    return safeString(url.toString(), maxLength);
  } catch {
    return safeString(input.split("?")[0].split("#")[0], maxLength);
  }
}

async function sha256Hex(input) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(String(input || ""));
    const digest = await crypto.subtle.digest("SHA-256", data);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return "";
  }
}

async function hashEmail(email) {
  const normalized = safeEmail(email);
  if (!normalized || !isValidEmailLike(normalized)) {
    return "";
  }

  const hashed = await sha256Hex(normalized);
  return hashed ? hashed.slice(0, 32) : "";
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
      viewportWidth: safeNumber(window?.innerWidth),
      viewportHeight: safeNumber(window?.innerHeight),
      timezone:
        safeString(
          Intl.DateTimeFormat?.().resolvedOptions?.().timeZone || "",
          100
        ) || "unknown",
      online: navigator?.onLine === true,
      webdriver: navigator?.webdriver === true,
      visibilityState: safeString(document?.visibilityState || "", 30),
      url: redactUrl(window?.location?.href || "", MAX_URL_LENGTH),
      referrer: redactUrl(document?.referrer || "", MAX_REFERRER_LENGTH)
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
    return Array.from(array, (part) => part.toString(16).padStart(8, "0")).join("-");
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

function cleanupRecentEvents(now = Date.now()) {
  for (const [key, timestamp] of recentEventMap.entries()) {
    if (now - timestamp > DEDUPE_WINDOW_MS) {
      recentEventMap.delete(key);
    }
  }
}

function buildDeduplicationKey(data = {}) {
  return [
    safeType(data.type),
    safeLevel(data.level),
    safeString(data.message || "", 160),
    safeString(data.userId || "", 80)
  ].join("|");
}

function allowClientLog(data = {}) {
  const now = Date.now();

  cleanupRecentEvents(now);

  if (now - logWindowStart > CLIENT_LOG_WINDOW) {
    logWindowStart = now;
    logCounter = 0;
  }

  const dedupeKey = buildDeduplicationKey(data);
  const lastSeen = recentEventMap.get(dedupeKey);

  if (lastSeen && now - lastSeen < DEDUPE_WINDOW_MS) {
    return false;
  }

  logCounter += 1;

  if (logCounter > CLIENT_LOG_RATE_LIMIT) {
    return false;
  }

  recentEventMap.set(dedupeKey, now);
  return true;
}

/* ---------------- ABORT SIGNAL ---------------- */

function createAbortSignal(timeoutMs = REQUEST_TIMEOUT_MS) {
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

/* ---------------- PAYLOAD BUILDING ---------------- */

async function buildPayload(data = {}) {
  const rawEmail = safeEmail(data.email || "");
  const emailHash = await hashEmail(rawEmail);

  return {
    type: safeType(data.type),
    level: safeLevel(data.level),
    message: safeString(data.message || "", MAX_MESSAGE_LENGTH),
    email: "", // do not send raw email from client logs
    emailHash,
    userId: safeUserId(data.userId || ""),
    eventAt: Date.now(),
    sessionId: getSessionId(),
    metadata: sanitizeMetadata(data.metadata || {}),
    client: buildClientSnapshot()
  };
}

/* ---------------- MAIN LOGGER ---------------- */

export async function logSecurityEvent(data = {}) {
  try {
    if (!allowClientLog(data)) {
      return;
    }

    const payload = await buildPayload(data);
    const { signal, cleanup } = createAbortSignal(REQUEST_TIMEOUT_MS);

    try {
      await fetch("/api/security-log", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload),
        keepalive: true,
        signal,
        cache: "no-store"
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
