function toNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

export function analyzeBotBehavior(behavior = {}, req = null) {
  const now = Date.now();

  const pageLoadedAt = toNumber(behavior.pageLoadedAt, 0);
  const firstInteractionAt = toNumber(behavior.firstInteractionAt, 0);
  const submitAt = toNumber(behavior.submitAt, now);

  const mouseMoves = toNumber(behavior.mouseMoves, 0);
  const keyPresses = toNumber(behavior.keyPresses, 0);
  const clicks = toNumber(behavior.clicks, 0);
  const touches = toNumber(behavior.touches, 0);
  const scrolls = toNumber(behavior.scrolls, 0);
  const visibilityChanges = toNumber(behavior.visibilityChanges, 0);

  const sessionId = safeString(behavior.sessionId || "", 120);

  const requestUserAgent = safeString(req?.headers["user-agent"] || "", 500);
  const behaviorUserAgent = safeString(behavior.userAgent || "", 500);
  const userAgent = requestUserAgent || behaviorUserAgent;

  const totalInteractions =
    mouseMoves + keyPresses + clicks + touches + scrolls;

  const timeOnPageMs =
    pageLoadedAt > 0 && submitAt >= pageLoadedAt
      ? submitAt - pageLoadedAt
      : 0;

  const timeToFirstInteractionMs =
    firstInteractionAt > 0 && pageLoadedAt > 0 && firstInteractionAt >= pageLoadedAt
      ? firstInteractionAt - pageLoadedAt
      : null;

  let riskScore = 0;
  const reasons = [];

  if (!sessionId) {
    riskScore += 15;
    reasons.push("missing_session_id");
  }

  if (timeOnPageMs > 0 && timeOnPageMs < 1200) {
    riskScore += 30;
    reasons.push("submitted_too_fast");
  }

  if (timeOnPageMs > 0 && timeOnPageMs < 2500 && totalInteractions === 0) {
    riskScore += 35;
    reasons.push("no_interaction_before_submit");
  }

  if (timeToFirstInteractionMs !== null && timeToFirstInteractionMs < 100) {
    riskScore += 15;
    reasons.push("interaction_too_fast");
  }

  if (totalInteractions === 0) {
    riskScore += 20;
    reasons.push("zero_interactions");
  }

  if (mouseMoves === 0 && keyPresses === 0 && touches === 0 && clicks === 0) {
    riskScore += 10;
    reasons.push("no_direct_input_signals");
  }

  if (visibilityChanges > 10) {
    riskScore += 10;
    reasons.push("excessive_visibility_changes");
  }

  if (/headless|phantom|selenium|playwright|puppeteer|crawler|spider|bot/i.test(userAgent)) {
    riskScore += 50;
    reasons.push("suspicious_user_agent");
  }

  let level = "low";
  if (riskScore >= 70) {
    level = "high";
  } else if (riskScore >= 40) {
    level = "medium";
  }

  return {
    riskScore,
    level,
    reasons,
    signals: {
      timeOnPageMs,
      timeToFirstInteractionMs,
      totalInteractions,
      mouseMoves,
      keyPresses,
      clicks,
      touches,
      scrolls,
      visibilityChanges,
      sessionIdPresent: Boolean(sessionId)
    }
  };
}
