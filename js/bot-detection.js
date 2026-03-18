const behaviorState = {
  pageLoadedAt: Date.now(),
  firstInteractionAt: 0,
  submitAt: 0,
  mouseMoves: 0,
  keyPresses: 0,
  clicks: 0,
  touches: 0,
  scrolls: 0,
  visibilityChanges: 0,
  sessionId: "",
  route: window.location.pathname || "unknown-route",
  userAgent: navigator.userAgent || "",
  initialized: false
};

function ensureFirstInteraction() {
  if (!behaviorState.firstInteractionAt) {
    behaviorState.firstInteractionAt = Date.now();
  }
}

function safeSessionId() {
  try {
    const key = "aethra_session_id";
    let sessionId = sessionStorage.getItem(key);

    if (!sessionId) {
      sessionId =
        "sess_" +
        Math.random().toString(36).slice(2) +
        "_" +
        Date.now().toString(36);
      sessionStorage.setItem(key, sessionId);
    }

    return sessionId;
  } catch {
    return "session_unavailable";
  }
}

function initBotDetection() {
  if (behaviorState.initialized) return;

  behaviorState.sessionId = safeSessionId();

  window.addEventListener("mousemove", () => {
    behaviorState.mouseMoves += 1;
    ensureFirstInteraction();
  }, { passive: true });

  window.addEventListener("keydown", () => {
    behaviorState.keyPresses += 1;
    ensureFirstInteraction();
  }, { passive: true });

  window.addEventListener("click", () => {
    behaviorState.clicks += 1;
    ensureFirstInteraction();
  }, { passive: true });

  window.addEventListener("touchstart", () => {
    behaviorState.touches += 1;
    ensureFirstInteraction();
  }, { passive: true });

  window.addEventListener("scroll", () => {
    behaviorState.scrolls += 1;
    ensureFirstInteraction();
  }, { passive: true });

  document.addEventListener("visibilitychange", () => {
    behaviorState.visibilityChanges += 1;
  }, { passive: true });

  behaviorState.initialized = true;
}

export function markSubmitAttempt() {
  behaviorState.submitAt = Date.now();
}

export function detectBotBehavior() {
  return {
    pageLoadedAt: behaviorState.pageLoadedAt,
    firstInteractionAt: behaviorState.firstInteractionAt,
    submitAt: behaviorState.submitAt || Date.now(),
    mouseMoves: behaviorState.mouseMoves,
    keyPresses: behaviorState.keyPresses,
    clicks: behaviorState.clicks,
    touches: behaviorState.touches,
    scrolls: behaviorState.scrolls,
    visibilityChanges: behaviorState.visibilityChanges,
    sessionId: behaviorState.sessionId || safeSessionId(),
    route: behaviorState.route,
    userAgent: behaviorState.userAgent
  };
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initBotDetection, { once: true });
} else {
  initBotDetection();
}
