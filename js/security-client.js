const MAX_COUNTER = 5000;
const SESSION_KEY = "aethra_session_id";
const TELEMETRY_VERSION = 2;

const securityState = {
  pageLoadedAt: Date.now(),
  firstInteractionAt: null,
  mouseMoves: 0,
  keyPresses: 0,
  touches: 0,
  clicks: 0,
  scrolls: 0,
  visibilityChanges: 0,
  lastVisibilityState: document.visibilityState,
  sessionId: getOrCreateSessionId()
};

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeCounter(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0) {
    return 0;
  }

  return Math.min(MAX_COUNTER, Math.floor(num));
}

function safeStorageGet(key) {
  try {
    return sessionStorage.getItem(key);
  } catch (error) {
    return null;
  }
}

function safeStorageSet(key, value) {
  try {
    sessionStorage.setItem(key, value);
    return true;
  } catch (error) {
    return false;
  }
}

function createFallbackSessionId() {
  return `sess_${Date.now()}_${Math.random().toString(36).slice(2, 12)}`;
}

function generateSessionId() {
  try {
    if (globalThis.crypto?.randomUUID) {
      return `sess_${crypto.randomUUID()}`;
    }
  } catch (error) {
    // ignore and fall back below
  }

  return createFallbackSessionId();
}

function getOrCreateSessionId() {
  let value = safeStorageGet(SESSION_KEY);

  if (!value) {
    value = generateSessionId();
    safeStorageSet(SESSION_KEY, value);
  }

  return safeString(value, 120);
}

function incrementCounter(key) {
  securityState[key] = safeCounter(securityState[key] + 1);
}

function markInteraction() {
  if (!securityState.firstInteractionAt) {
    securityState.firstInteractionAt = Date.now();
  }
}

document.addEventListener("mousemove", () => {
  incrementCounter("mouseMoves");
  markInteraction();
}, { passive: true });

document.addEventListener("keydown", () => {
  incrementCounter("keyPresses");
  markInteraction();
}, { passive: true });

document.addEventListener("touchstart", () => {
  incrementCounter("touches");
  markInteraction();
}, { passive: true });

document.addEventListener("click", () => {
  incrementCounter("clicks");
  markInteraction();
}, { passive: true });

document.addEventListener("scroll", () => {
  incrementCounter("scrolls");
  markInteraction();
}, { passive: true });

document.addEventListener("visibilitychange", () => {
  incrementCounter("visibilityChanges");
  securityState.lastVisibilityState = safeString(document.visibilityState, 30);
});

function getScreenInfo() {
  return {
    screenWidth: Number.isFinite(window.screen?.width) ? window.screen.width : 0,
    screenHeight: Number.isFinite(window.screen?.height) ? window.screen.height : 0,
    viewportWidth: Number.isFinite(window.innerWidth) ? window.innerWidth : 0,
    viewportHeight: Number.isFinite(window.innerHeight) ? window.innerHeight : 0,
    pixelRatio: Number.isFinite(window.devicePixelRatio) ? window.devicePixelRatio : 1
  };
}

function getDeviceInfo() {
  return {
    timezone: safeString(Intl.DateTimeFormat().resolvedOptions().timeZone || "", 100),
    language: safeString(navigator.language || "", 40),
    platform: safeString(navigator.platform || "", 100),
    userAgent: safeString(navigator.userAgent || "", 500),
    hardwareConcurrency: Number.isFinite(navigator.hardwareConcurrency)
      ? navigator.hardwareConcurrency
      : 0,
    deviceMemory: Number.isFinite(navigator.deviceMemory)
      ? navigator.deviceMemory
      : 0,
    isTouchDevice: (
      "ontouchstart" in window ||
      navigator.maxTouchPoints > 0 ||
      navigator.msMaxTouchPoints > 0
    )
  };
}

export function getSecurityBehaviorPayload() {
  return {
    telemetryVersion: TELEMETRY_VERSION,
    pageLoadedAt: securityState.pageLoadedAt,
    firstInteractionAt: securityState.firstInteractionAt,
    submitAt: Date.now(),
    mouseMoves: safeCounter(securityState.mouseMoves),
    keyPresses: safeCounter(securityState.keyPresses),
    touches: safeCounter(securityState.touches),
    clicks: safeCounter(securityState.clicks),
    scrolls: safeCounter(securityState.scrolls),
    visibilityChanges: safeCounter(securityState.visibilityChanges),
    visibilityState: safeString(securityState.lastVisibilityState, 30),
    sessionId: safeString(securityState.sessionId, 120),
    ...getScreenInfo(),
    ...getDeviceInfo()
  };
}

export function resetSecurityBehaviorCounters() {
  securityState.firstInteractionAt = null;
  securityState.mouseMoves = 0;
  securityState.keyPresses = 0;
  securityState.touches = 0;
  securityState.clicks = 0;
  securityState.scrolls = 0;
  securityState.visibilityChanges = 0;
  securityState.lastVisibilityState = safeString(document.visibilityState, 30);
  securityState.pageLoadedAt = Date.now();
}

export function getSecuritySessionId() {
  return safeString(securityState.sessionId, 120);
}
