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

    return value;
  } catch {
    return `sess_fallback_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  }
}

function markFirstInteraction() {
  if (!botDetectionState.firstInteractionAt) {
    botDetectionState.firstInteractionAt = Date.now();
  }
}

document.addEventListener(
  "mousemove",
  () => {
    botDetectionState.mouseMoves += 1;
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener(
  "keydown",
  () => {
    botDetectionState.keyPresses += 1;
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener(
  "click",
  () => {
    botDetectionState.clicks += 1;
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener(
  "touchstart",
  () => {
    botDetectionState.touches += 1;
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener(
  "scroll",
  () => {
    botDetectionState.scrolls += 1;
    markFirstInteraction();
  },
  { passive: true }
);

document.addEventListener("visibilitychange", () => {
  botDetectionState.visibilityChanges += 1;
  botDetectionState.lastVisibilityState = document.visibilityState || "unknown";
});

function safeNavigatorValue(value) {
  return String(value || "").slice(0, 300);
}

export function detectBotBehavior() {
  const submitAt = Date.now();
  const pageLoadedAt = botDetectionState.pageLoadedAt;
  const firstInteractionAt = botDetectionState.firstInteractionAt;

  const timeOnPageMs = Math.max(0, submitAt - pageLoadedAt);
  const timeToFirstInteractionMs =
    firstInteractionAt && firstInteractionAt >= pageLoadedAt
      ? firstInteractionAt - pageLoadedAt
      : null;

  const totalInteractions =
    botDetectionState.mouseMoves +
    botDetectionState.keyPresses +
    botDetectionState.clicks +
    botDetectionState.touches +
    botDetectionState.scrolls;

  return {
    pageLoadedAt,
    firstInteractionAt,
    submitAt,
    timeOnPageMs,
    timeToFirstInteractionMs,
    totalInteractions,
    mouseMoves: botDetectionState.mouseMoves,
    keyPresses: botDetectionState.keyPresses,
    clicks: botDetectionState.clicks,
    touches: botDetectionState.touches,
    scrolls: botDetectionState.scrolls,
    visibilityChanges: botDetectionState.visibilityChanges,
    visibilityState: botDetectionState.lastVisibilityState,
    sessionId: botDetectionState.sessionId,
    timezone: safeNavigatorValue(
      Intl.DateTimeFormat().resolvedOptions().timeZone || ""
    ),
    language: safeNavigatorValue(navigator.language || ""),
    platform: safeNavigatorValue(navigator.platform || ""),
    userAgent: safeNavigatorValue(navigator.userAgent || ""),
    screenWidth: window.screen?.width || 0,
    screenHeight: window.screen?.height || 0
  };
}
