function toNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function toSafeInt(value, fallback = 0, min = 0, max = 1_000_000_000) {
  const num = Math.floor(toNumber(value, fallback));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function isSuspiciousUserAgent(userAgent) {
  return /headless|phantom|selenium|playwright|puppeteer|crawler|spider|bot/i.test(userAgent);
}

export function analyzeBotBehavior(behavior = {}, req = null) {
  const now = Date.now();

  const pageLoadedAt = toSafeInt(behavior.pageLoadedAt, 0, 0, now + 60_000);
  const firstInteractionAt = toSafeInt(behavior.firstInteractionAt, 0, 0, now + 60_000);
  const submitAt = toSafeInt(behavior.submitAt, now, 0, now + 60_000);

  const mouseMoves = toSafeInt(behavior.mouseMoves, 0, 0, 5000);
  const keyPresses = toSafeInt(behavior.keyPresses, 0, 0, 5000);
  const clicks = toSafeInt(behavior.clicks, 0, 0, 5000);
  const touches = toSafeInt(behavior.touches, 0, 0, 5000);
  const scrolls = toSafeInt(behavior.scrolls, 0, 0, 5000);
  const visibilityChanges = toSafeInt(behavior.visibilityChanges, 0, 0, 5000);

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
    firstInteractionAt > 0 &&
    pageLoadedAt > 0 &&
    firstInteractionAt >= pageLoadedAt
      ? firstInteractionAt - pageLoadedAt
      : null;

  let riskScore = 0;
  const reasons = [];

  if (!sessionId) {
    riskScore += 15;
    reasons.push("missing_session_id");
  }

  if (pageLoadedAt > 0 && submitAt > 0 && submitAt < pageLoadedAt) {
    riskScore += 20;
    reasons.push("invalid_submit_timeline");
  }

  if (
    firstInteractionAt > 0 &&
    pageLoadedAt > 0 &&
    firstInteractionAt < pageLoadedAt
  ) {
    riskScore += 15;
    reasons.push("invalid_interaction_timeline");
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

  if (requestUserAgent && behaviorUserAgent && requestUserAgent !== behaviorUserAgent) {
    riskScore += 10;
    reasons.push("user_agent_mismatch");
  }

  if (isSuspiciousUserAgent(userAgent)) {
    riskScore += 50;
    reasons.push("suspicious_user_agent");
  }

  riskScore = Math.min(100, riskScore);

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
      sessionIdPresent: Boolean(sessionId),
      requestUserAgentPresent: Boolean(requestUserAgent),
      behaviorUserAgentPresent: Boolean(behaviorUserAgent)
    }
  };
}
