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

function normalizeRoute(route) {
  return safeString(route || "unknown-route", 150).toLowerCase();
}

function isSuspiciousUserAgent(userAgent) {
  return /headless|phantom|selenium|playwright|puppeteer|crawler|spider|bot|curl|wget|python|axios|node-fetch/i.test(
    userAgent
  );
}

function getRouteSensitivity(route) {
  const normalized = normalizeRoute(route);

  if (
    normalized.includes("login") ||
    normalized.includes("signup") ||
    normalized.includes("verify") ||
    normalized.includes("developer") ||
    normalized.includes("admin")
  ) {
    return 2;
  }

  return 1;
}

function getRecommendedAction({ riskScore, telemetryQualityScore, hardBlockSignals }) {
  if (hardBlockSignals > 0 || riskScore >= 90) {
    return "block";
  }

  if (riskScore >= 65) {
    return "challenge";
  }

  if (riskScore >= 40 || telemetryQualityScore <= 30) {
    return "throttle";
  }

  return "allow";
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
  const route = normalizeRoute(behavior.route || req?.url || "unknown-route");

  const requestUserAgent = safeString(req?.headers?.["user-agent"] || "", 500);
  const behaviorUserAgent = safeString(behavior.userAgent || "", 500);
  const userAgent = requestUserAgent || behaviorUserAgent;

  const totalInteractions =
    mouseMoves + keyPresses + clicks + touches + scrolls;

  const directInputs = mouseMoves + keyPresses + clicks + touches;

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
  let telemetryQualityScore = 100;
  let hardBlockSignals = 0;
  const reasons = [];
  const telemetryWarnings = [];

  const routeSensitivity = getRouteSensitivity(route);

  if (!sessionId) {
    riskScore += 10;
    telemetryQualityScore -= 20;
    reasons.push("missing_session_id");
    telemetryWarnings.push("missing_session_id");
  }

  if (pageLoadedAt > 0 && submitAt > 0 && submitAt < pageLoadedAt) {
    riskScore += 30;
    hardBlockSignals += 1;
    reasons.push("invalid_submit_timeline");
  }

  if (
    firstInteractionAt > 0 &&
    pageLoadedAt > 0 &&
    firstInteractionAt < pageLoadedAt
  ) {
    riskScore += 20;
    reasons.push("invalid_interaction_timeline");
  }

  if (submitAt > now + 10_000 || pageLoadedAt > now + 10_000) {
    riskScore += 20;
    reasons.push("future_timestamp_pattern");
  }

  if (timeOnPageMs > 0 && timeOnPageMs < 1200) {
    riskScore += 25 * routeSensitivity;
    reasons.push("submitted_too_fast");
  }

  if (timeOnPageMs > 0 && timeOnPageMs < 2500 && totalInteractions === 0) {
    riskScore += 30 * routeSensitivity;
    reasons.push("no_interaction_before_submit");
  }

  if (timeToFirstInteractionMs !== null && timeToFirstInteractionMs < 100) {
    riskScore += 15;
    reasons.push("interaction_too_fast");
  }

  if (totalInteractions === 0) {
    riskScore += 15;
    reasons.push("zero_interactions");
  }

  if (directInputs === 0) {
    riskScore += 10;
    reasons.push("no_direct_input_signals");
  }

  if (visibilityChanges > 10) {
    riskScore += 10;
    reasons.push("excessive_visibility_changes");
  }

  if (requestUserAgent && behaviorUserAgent && requestUserAgent !== behaviorUserAgent) {
    riskScore += 15;
    reasons.push("user_agent_mismatch");
  }

  if (!requestUserAgent && !behaviorUserAgent) {
    telemetryQualityScore -= 20;
    telemetryWarnings.push("missing_user_agent");
  }

  if (isSuspiciousUserAgent(userAgent)) {
    riskScore += 50;
    hardBlockSignals += 1;
    reasons.push("suspicious_user_agent");
  }

  if (
    totalInteractions > 0 &&
    timeOnPageMs > 0 &&
    totalInteractions >= 100 &&
    timeOnPageMs < 1500
  ) {
    riskScore += 25;
    reasons.push("interaction_density_too_high");
  }

  if (
    keyPresses > 0 &&
    clicks === 0 &&
    mouseMoves === 0 &&
    touches === 0 &&
    timeOnPageMs > 0 &&
    timeOnPageMs < 1500
  ) {
    riskScore += 15;
    reasons.push("unnatural_input_pattern");
  }

  if (pageLoadedAt === 0) {
    telemetryQualityScore -= 20;
    telemetryWarnings.push("missing_page_loaded_at");
  }

  if (submitAt === 0) {
    telemetryQualityScore -= 20;
    telemetryWarnings.push("missing_submit_at");
  }

  if (firstInteractionAt === 0 && totalInteractions > 0) {
    telemetryQualityScore -= 10;
    telemetryWarnings.push("missing_first_interaction_at");
  }

  telemetryQualityScore = Math.max(0, Math.min(100, telemetryQualityScore));
  riskScore = Math.min(100, riskScore);

  let level = "low";
  if (riskScore >= 70) {
    level = "high";
  } else if (riskScore >= 40) {
    level = "medium";
  }

  const recommendedAction = getRecommendedAction({
    riskScore,
    telemetryQualityScore,
    hardBlockSignals
  });

  return {
    riskScore,
    level,
    recommendedAction,
    telemetryQualityScore,
    hardBlockSignals,
    reasons,
    telemetryWarnings,
    signals: {
      route,
      routeSensitivity,
      timeOnPageMs,
      timeToFirstInteractionMs,
      totalInteractions,
      directInputs,
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
