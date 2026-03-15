function getOrCreateSessionId() {
  const key = "aethra_session_id";

  try {
    let value = sessionStorage.getItem(key);

    if (!value) {
      value =
        typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
          ? `sess_${crypto.randomUUID()}`
          : `sess_${Date.now()}_${Math.random().toString(16).slice(2)}`;

      sessionStorage.setItem(key, value);
    }

    return String(value).slice(0, 120);
  } catch {
    return `sess_fallback_${Date.now()}_${Math.random().toString(16).slice(2)}`.slice(0, 120);
  }
}

const MAX_COUNTER = 5000;

const botDetectionState = {
  pageLoadedAt: Date.now(),
  firstInteractionAt: null,
  mouseMoves: 0,
  keyPresses: 0,
  clicks: 0,
  touches: 0,
  scrolls: 0,
  visibilityChanges: 0,
  lastVisibilityState: document.visibilityState || "visible",
  sessionId: getOrCreateSessionId()
};

function incrementCounter(key) {
  if (typeof botDetectionState[key] !== "number") {
    botDetectionState[key] = 0;
  }

  botDetectionState[key] = Math.min(MAX_COUNTER, botDetectionState[key] + 1);
}

function markFirstInteraction() {
  if (!botDetectionState.firstInteractionAt) {
    botDetectionState.firstInteractionAt = Date.now();
  }
}

let lastMouseMoveAt = 0;
let lastScrollAt = 0;

document.addEventListener(
  "mousemove",
  () => {
    const now = Date.now();

    if (now - lastMouseMoveAt > 50) {
      incrementCounter("mouseMoves");
      markFirstInteraction();
      lastMouseMoveAt = now;
    }
  },
  { passive: true }
);

document.addEventListener(
  "keydown",
  () => {
    incrementCounter("keyPresses");
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener(
  "click",
  () => {
    incrementCounter("clicks");
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener(
  "touchstart",
  () => {
    incrementCounter("touches");
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener(
  "scroll",
  () => {
    const now = Date.now();

    if (now - lastScrollAt > 100) {
      incrementCounter("scrolls");
      markFirstInteraction();
      lastScrollAt = now;
    }
  },
  { passive: true }
);

document.addEventListener("visibilitychange", () => {
  incrementCounter("visibilityChanges");
  botDetectionState.lastVisibilityState = document.visibilityState || "unknown";
});

function safeNavigatorValue(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeTimezone() {
  try {
    return safeNavigatorValue(
      Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      100
    );
  } catch {
    return "";
  }
}

export function detectBotBehavior() {
  const submitAt = Date.now();
  const pageLoadedAt = safeNumber(botDetectionState.pageLoadedAt, submitAt);
  const firstInteractionAt = safeNumber(botDetectionState.firstInteractionAt, 0) || null;

  const timeOnPageMs = Math.max(0, submitAt - pageLoadedAt);
  const timeToFirstInteractionMs =
    firstInteractionAt && firstInteractionAt >= pageLoadedAt
      ? firstInteractionAt - pageLoadedAt
      : null;

  const mouseMoves = safeNumber(botDetectionState.mouseMoves);
  const keyPresses = safeNumber(botDetectionState.keyPresses);
  const clicks = safeNumber(botDetectionState.clicks);
  const touches = safeNumber(botDetectionState.touches);
  const scrolls = safeNumber(botDetectionState.scrolls);

  const totalInteractions =
    mouseMoves + keyPresses + clicks + touches + scrolls;

  return {
    pageLoadedAt,
    firstInteractionAt,
    submitAt,
    timeOnPageMs,
    timeToFirstInteractionMs,
    totalInteractions,
    mouseMoves,
    keyPresses,
    clicks,
    touches,
    scrolls,
    visibilityChanges: safeNumber(botDetectionState.visibilityChanges),
    visibilityState: safeNavigatorValue(botDetectionState.lastVisibilityState, 40),
    sessionId: safeNavigatorValue(botDetectionState.sessionId, 120),
    timezone: safeTimezone(),
    language: safeNavigatorValue(navigator.language || "", 50),
    platform: safeNavigatorValue(navigator.platform || "", 100),
    userAgent: safeNavigatorValue(navigator.userAgent || "", 300),
    screenWidth: safeNumber(window.screen?.width),
    screenHeight: safeNumber(window.screen?.height)
  };
}
