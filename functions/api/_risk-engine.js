const MAX_REASON_LENGTH = 100;
const MAX_REASONS = 50;

const ALLOWED_LEVELS = new Set(["low", "medium", "high", "critical"]);
const ALLOWED_ACTIONS = new Set(["allow", "throttle", "challenge", "block"]);
const ALLOWED_ROUTE_SENSITIVITY = new Set(["normal", "high", "critical"]);

function safeString(value, maxLength = 300) {
  return String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeInt(value, fallback = 0, min = 0, max = 1_000_000) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function normalizeLevel(value = "low") {
  const normalized = safeString(value, 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "low";
}

function normalizeAction(value = "allow") {
  const normalized = safeString(value, 20).toLowerCase();
  return ALLOWED_ACTIONS.has(normalized) ? normalized : "allow";
}

function normalizeRouteSensitivity(value = "normal") {
  const normalized = safeString(value, 20).toLowerCase();
  return ALLOWED_ROUTE_SENSITIVITY.has(normalized)
    ? normalized
    : "normal";
}

function pushReason(reasons, reason) {
  const safeReason = safeString(reason, MAX_REASON_LENGTH);
  if (!safeReason) return;

  if (!reasons.includes(safeReason)) {
    reasons.push(safeReason);
  }
}

function addWeightedScore(state, amount, reason) {
  state.score += safeInt(amount, 0, 0, 1000);

  if (reason) {
    pushReason(state.reasons, reason);
  }
}

function getLevel(score) {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function getAction(score, hardBlockSignals = 0) {
  const signals = safeInt(hardBlockSignals, 0, 0, 100);

  if (signals >= 2 || score >= 95) return "block";
  if (score >= 75) return "challenge";
  if (score >= 45) return "throttle";
  return "allow";
}

function normalizeArrayReasons(input = [], max = 20) {
  if (!Array.isArray(input)) return [];

  return input
    .slice(0, max)
    .map((r) => safeString(r, 80))
    .filter(Boolean);
}

function normalizeBotResult(botResult = null) {
  if (!botResult || typeof botResult !== "object") return null;

  return {
    riskScore: safeInt(botResult.riskScore, 0, 0, 100),
    level: normalizeLevel(botResult.level),
    recommendedAction: normalizeAction(botResult.recommendedAction),
    escalatedAction: normalizeAction(botResult.escalatedAction),
    telemetryQualityScore: safeInt(botResult.telemetryQualityScore, 100, 0, 100),
    hardBlockSignals: safeInt(botResult.hardBlockSignals, 0, 0, 20),

    distributed: {
      suspicionScore: safeInt(botResult?.distributed?.suspicionScore, 0, 0, 1000),
      hardBlockCount: safeInt(botResult?.distributed?.hardBlockCount, 0),
      suspiciousCount: safeInt(botResult?.distributed?.suspiciousCount, 0),
      sameRouteRecent: safeInt(botResult?.distributed?.sameRouteRecent, 0),
      recentChallenges: safeInt(botResult?.distributed?.recentChallenges, 0),
      recentHardBlocks: safeInt(botResult?.distributed?.recentHardBlocks, 0),
      sensitiveRouteHits: safeInt(botResult?.distributed?.sensitiveRouteHits, 0)
    },

    reasons: normalizeArrayReasons(botResult.reasons)
  };
}

function normalizeAbuseResult(abuseResult = null) {
  if (!abuseResult || typeof abuseResult !== "object") return null;

  return {
    abuseScore: safeInt(abuseResult.abuseScore, 0, 0, 100),
    level: normalizeLevel(abuseResult.level),
    recommendedAction: normalizeAction(abuseResult.recommendedAction),
    containmentAction: safeString(abuseResult.containmentAction || "none", 40),
    penaltyActive: Boolean(abuseResult.penaltyActive),

    snapshot: {
      weightedRequests: safeInt(abuseResult?.snapshot?.weightedRequests, 0),
      weightedFailures: safeInt(abuseResult?.snapshot?.weightedFailures, 0),
      uniqueRoutes: safeInt(abuseResult?.snapshot?.uniqueRoutes, 0),
      burstCount: safeInt(abuseResult?.snapshot?.burstCount, 0),
      criticalRouteTouchesRecent: safeInt(
        abuseResult?.snapshot?.criticalRouteTouchesRecent,
        0
      ),
      suspiciousEvents: safeInt(abuseResult?.snapshot?.suspiciousEvents, 0),
      penaltyCount: safeInt(abuseResult?.snapshot?.penaltyCount, 0)
    },

    reasons: normalizeArrayReasons(abuseResult.reasons)
  };
}

function normalizeRateLimitResult(rateLimitResult = null) {
  if (!rateLimitResult || typeof rateLimitResult !== "object") return null;

  return {
    allowed: Boolean(rateLimitResult.allowed),
    recommendedAction: normalizeAction(rateLimitResult.recommendedAction),
    containmentAction: safeString(rateLimitResult.containmentAction || "none", 40),
    penaltyActive: Boolean(rateLimitResult.penaltyActive),

    overBy: safeInt(rateLimitResult.overBy, 0),
    violations: safeInt(rateLimitResult.violations, 0),
    burstCount: safeInt(rateLimitResult.burstCount, 0),
    routeSensitivity: normalizeRouteSensitivity(
      rateLimitResult.routeSensitivity
    ),
    highestCountSeen: safeInt(rateLimitResult.highestCountSeen, 0)
  };
}

function normalizeFreshnessResult(freshnessResult = null) {
  if (!freshnessResult || typeof freshnessResult !== "object") return null;

  return {
    ok: Boolean(freshnessResult.ok),
    code: safeString(freshnessResult.code || "", 100),
    ageMs: safeNumber(freshnessResult.ageMs, 0)
  };
}

function normalizeThreatResult(threatResult = null) {
  if (!threatResult || typeof threatResult !== "object") return null;

  return {
    threatScore: safeInt(threatResult.threatScore, 0, 0, 100),
    level: normalizeLevel(threatResult.level),
    action: normalizeAction(threatResult.action),

    events: {
      botEvents: safeInt(threatResult?.events?.botEvents, 0),
      abuseEvents: safeInt(threatResult?.events?.abuseEvents, 0),
      rateLimitEvents: safeInt(threatResult?.events?.rateLimitEvents, 0),
      freshnessFailures: safeInt(threatResult?.events?.freshnessFailures, 0),
      blockEvents: safeInt(threatResult?.events?.blockEvents, 0),
      hardBlockSignals: safeInt(threatResult?.events?.hardBlockSignals, 0),
      criticalRouteHits: safeInt(threatResult?.events?.criticalRouteHits, 0)
    }
  };
}

function normalizeSecurityState(securityState = null) {
  if (!securityState || typeof securityState !== "object") return null;

  return {
    currentRiskScore: safeInt(securityState.currentRiskScore, 0, 0, 100),
    currentRiskLevel: normalizeLevel(securityState.currentRiskLevel),
    failedLoginCount: safeInt(securityState.failedLoginCount, 0),
    failedSignupCount: safeInt(securityState.failedSignupCount, 0),
    failedPasswordResetCount: safeInt(
      securityState.failedPasswordResetCount,
      0
    ),
    captchaFailureCount: safeInt(securityState.captchaFailureCount, 0),
    suspiciousEventCount: safeInt(securityState.suspiciousEventCount, 0),
    rateLimitHitCount: safeInt(securityState.rateLimitHitCount, 0),
    lockoutCount: safeInt(securityState.lockoutCount, 0),
    successfulAuthCount: safeInt(securityState.successfulAuthCount, 0)
  };
}

export function evaluateRisk(inputs = {}) {
  const botResult = normalizeBotResult(inputs.botResult);
  const abuseResult = normalizeAbuseResult(inputs.abuseResult);
  const rateLimitResult = normalizeRateLimitResult(inputs.rateLimitResult);
  const freshnessResult = normalizeFreshnessResult(inputs.freshnessResult);
  const threatResult = normalizeThreatResult(inputs.threatResult);
  const securityState = normalizeSecurityState(inputs.securityState);
  const routeSensitivity = normalizeRouteSensitivity(
    inputs.routeSensitivity || "normal"
  );

  const state = {
    score: 0,
    reasons: [],
    hardBlockSignals: 0
  };

  /* ROUTE SENSITIVITY */

  if (routeSensitivity === "critical") addWeightedScore(state, 8, "route:critical");
  if (routeSensitivity === "high") addWeightedScore(state, 4, "route:high");

  /* BOT SIGNALS */

  if (botResult) {
    if (botResult.riskScore >= 70) addWeightedScore(state, 20, "bot:high_risk");
    else if (botResult.riskScore >= 40) addWeightedScore(state, 10, "bot:medium_risk");

    if (botResult.escalatedAction === "block")
      addWeightedScore(state, 20, "bot:escalated_block");

    if (botResult.escalatedAction === "challenge")
      addWeightedScore(state, 10, "bot:escalated_challenge");

    if (botResult.telemetryQualityScore <= 30)
      addWeightedScore(state, 10, "bot:low_telemetry_quality");

    if (botResult.distributed.suspicionScore >= 120)
      addWeightedScore(state, 25, "bot:distributed_suspicion_high");

    else if (botResult.distributed.suspicionScore >= 60)
      addWeightedScore(state, 12, "bot:distributed_suspicion_medium");

    if (botResult.distributed.recentHardBlocks >= 2)
      addWeightedScore(state, 15, "bot:recent_hard_blocks");

    if (botResult.distributed.recentChallenges >= 3)
      addWeightedScore(state, 8, "bot:recent_challenges");

    if (botResult.distributed.sensitiveRouteHits >= 5)
      addWeightedScore(state, 10, "bot:sensitive_route_targeting");

    if (botResult.hardBlockSignals > 0) {
      state.hardBlockSignals += botResult.hardBlockSignals;
      addWeightedScore(state, 35, "bot:hard_block_signal");
    }

    if (botResult.distributed.hardBlockCount >= 2) {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 20, "bot:distributed_hard_block_history");
    }

    for (const reason of botResult.reasons) {
      pushReason(state.reasons, `bot:${reason}`);
    }
  }

  /* ABUSE */

  if (abuseResult) {
    if (abuseResult.abuseScore >= 70)
      addWeightedScore(state, 22, "abuse:high_score");

    else if (abuseResult.abuseScore >= 40)
      addWeightedScore(state, 10, "abuse:medium_score");

    if (abuseResult.penaltyActive)
      addWeightedScore(state, 18, "abuse:penalty_active");

    if (abuseResult.snapshot.weightedFailures >= 12)
      addWeightedScore(state, 15, "abuse:heavy_failures");

    if (abuseResult.snapshot.uniqueRoutes >= 4)
      addWeightedScore(state, 10, "abuse:multi_route_probing");

    if (abuseResult.snapshot.criticalRouteTouchesRecent >= 2)
      addWeightedScore(state, 20, "abuse:critical_route_targeting");

    for (const reason of abuseResult.reasons) {
      pushReason(state.reasons, `abuse:${reason}`);
    }
  }

  /* RATE LIMIT */

  if (rateLimitResult) {
    if (!rateLimitResult.allowed)
      addWeightedScore(state, 15, "rate:limit_exceeded");

    if (rateLimitResult.penaltyActive)
      addWeightedScore(state, 15, "rate:penalty_active");

    if (rateLimitResult.violations >= 4)
      addWeightedScore(state, 18, "rate:repeat_violations");

    if (rateLimitResult.burstCount >= 10)
      addWeightedScore(state, 15, "rate:burst_pattern");

    if (rateLimitResult.routeSensitivity === "critical")
      addWeightedScore(state, 10, "rate:critical_route_pressure");
  }

  /* REQUEST FRESHNESS */

  if (freshnessResult && !freshnessResult.ok) {
    addWeightedScore(
      state,
      20,
      `freshness:${freshnessResult.code || "failed"}`
    );

    if (
      freshnessResult.code === "replayed_nonce" ||
      freshnessResult.code === "future_request_timestamp"
    ) {
      state.hardBlockSignals += 1;
    }
  }

  /* THREAT MEMORY */

  if (threatResult) {
    if (threatResult.threatScore >= 80)
      addWeightedScore(state, 25, "memory:high");

    else if (threatResult.threatScore >= 50)
      addWeightedScore(state, 12, "memory:medium");

    if (threatResult.events.blockEvents >= 3)
      addWeightedScore(state, 12, "memory:repeat_block_events");

    if (threatResult.events.hardBlockSignals >= 2) {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 15, "memory:hard_block_signals");
    }
  }

  /* SECURITY STATE */

  if (securityState) {
    if (securityState.currentRiskScore >= 75)
      addWeightedScore(state, 20, "state:high_risk_score");

    if (securityState.lockoutCount >= 2)
      addWeightedScore(state, 18, "state:lockout_history");

    if (securityState.currentRiskLevel === "critical") {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 15, "state:critical_risk_level");
    }
  }

  /* FINALIZE */

  state.score = Math.min(100, safeInt(state.score, 0, 0, 100));
  state.reasons = state.reasons.slice(0, MAX_REASONS);

  const level = getLevel(state.score);
  const action = getAction(state.score, state.hardBlockSignals);

  let containmentAction = "none";

  if (action === "block") {
    containmentAction =
      level === "critical"
        ? "freeze_sensitive_route"
        : "temporary_containment";
  } else if (action === "challenge") {
    containmentAction = "step_up_verification";
  } else if (action === "throttle") {
    containmentAction = "slow_down_actor";
  }

  return {
    riskScore: state.score,
    level,
    action,
    containmentAction,
    hardBlockSignals: safeInt(state.hardBlockSignals, 0, 0, 100),
    reasons: state.reasons
  };
}
