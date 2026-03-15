const securityState = {
  pageLoadedAt: Date.now(),
  firstInteractionAt: null,
  mouseMoves: 0,
  keyPresses: 0,
  touches: 0,
  clicks: 0,
  visibilityChanges: 0,
  lastVisibilityState: document.visibilityState,
  sessionId: getOrCreateSessionId()
};

function getOrCreateSessionId() {
  const key = "aethra_session_id";
  let value = sessionStorage.getItem(key);

  if (!value) {
    value = `sess_${crypto.randomUUID()}`;
    sessionStorage.setItem(key, value);
  }

  return value;
}

function markInteraction() {
  if (!securityState.firstInteractionAt) {
    securityState.firstInteractionAt = Date.now();
  }
}

document.addEventListener("mousemove", () => {
  securityState.mouseMoves += 1;
  markInteraction();
}, { passive: true });

document.addEventListener("keydown", () => {
  securityState.keyPresses += 1;
  markInteraction();
}, { passive: true });

document.addEventListener("touchstart", () => {
  securityState.touches += 1;
  markInteraction();
}, { passive: true });

document.addEventListener("click", () => {
  securityState.clicks += 1;
  markInteraction();
}, { passive: true });

document.addEventListener("visibilitychange", () => {
  securityState.visibilityChanges += 1;
  securityState.lastVisibilityState = document.visibilityState;
});

export function getSecurityBehaviorPayload() {
  return {
    pageLoadedAt: securityState.pageLoadedAt,
    firstInteractionAt: securityState.firstInteractionAt,
    submitAt: Date.now(),
    mouseMoves: securityState.mouseMoves,
    keyPresses: securityState.keyPresses,
    touches: securityState.touches,
    clicks: securityState.clicks,
    visibilityChanges: securityState.visibilityChanges,
    visibilityState: securityState.lastVisibilityState,
    sessionId: securityState.sessionId,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    language: navigator.language || "",
    platform: navigator.platform || "",
    userAgent: navigator.userAgent || ""
  };
}
