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

function createPressureBreakdown() {
  return {
    routePressure: 0,
    botPressure: 0,
    abusePressure: 0,
    ratePressure: 0,
    freshnessPressure: 0,
    payloadPressure: 0,
    memoryPressure: 0,
    statePressure: 0
  };
}

function createEventSignals() {
  return {
    exploitSignals: 0,
    breachSignals: 0,
    replaySignals: 0,
    coordinatedSignals: 0
  };
}

function addWeightedScore(state, amount, reason, pressureKey = "") {
  const safeAmount = safeInt(amount, 0, 0, 1000);
  state.score += safeAmount;

  if (pressureKey && state.pressures[pressureKey] !== undefined) {
    state.pressures[pressureKey] += safeAmount;
  }

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

function getAction(score, hardBlockSignals = 0, criticalSignals = 0, eventSignals = {}) {
  const hardSignals = safeInt(hardBlockSignals, 0, 0, 100);
  const severeSignals = safeInt(criticalSignals, 0, 0, 100);
  const exploitSignals = safeInt(eventSignals.exploitSignals, 0, 0, 100);
  const breachSignals = safeInt(eventSignals.breachSignals, 0, 0, 100);

  if (breachSignals > 0) return "block";
  if (exploitSignals > 0 && (hardSignals > 0 || severeSignals > 0)) return "block";
  if (hardSignals >= 2 || severeSignals >= 2 || score >= 95) return "block";
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
      sensitiveRouteHits: safeInt(botResult?.distributed?.sensitiveRouteHits, 0),
      uniqueRecentRoutes: safeInt(botResult?.distributed?.uniqueRecentRoutes, 0)
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
      uniqueCriticalRoutesRecent: safeInt(
        abuseResult?.snapshot?.uniqueCriticalRoutesRecent,
        0
      ),
      suspiciousEvents: safeInt(abuseResult?.snapshot?.suspiciousEvents, 0),
      penaltyCount: safeInt(abuseResult?.snapshot?.penaltyCount, 0),
      coordinatedProbe: abuseResult?.snapshot?.coordinatedProbe === true,
      breachLikePattern: abuseResult?.snapshot?.breachLikePattern === true
    },

    events: {
      burstEvents: safeInt(abuseResult?.events?.burstEvents, 0),
      probeEvents: safeInt(abuseResult?.events?.probeEvents, 0),
      criticalRouteHits: safeInt(abuseResult?.events?.criticalRouteHits, 0),
      breachSignals: safeInt(abuseResult?.events?.breachSignals, 0),
      hardBlockSignals: safeInt(abuseResult?.events?.hardBlockSignals, 0),
      endpointSpread: safeInt(abuseResult?.events?.endpointSpread, 0)
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
    degraded: rateLimitResult.degraded === true,

    overBy: safeInt(rateLimitResult.overBy, 0),
    violations: safeInt(rateLimitResult.violations, 0),
    burstCount: safeInt(rateLimitResult.burstCount, 0),
    routeSensitivity: normalizeRouteSensitivity(
      rateLimitResult.routeSensitivity
    ),
    highestCountSeen: safeInt(rateLimitResult.highestCountSeen, 0),

    events: {
      blockEvents: safeInt(rateLimitResult?.events?.blockEvents, 0),
      challengeEvents: safeInt(rateLimitResult?.events?.challengeEvents, 0),
      throttleEvents: safeInt(rateLimitResult?.events?.throttleEvents, 0),
      hardBlockSignals: safeInt(rateLimitResult?.events?.hardBlockSignals, 0),
      burstSignals: safeInt(rateLimitResult?.events?.burstSignals, 0),
      criticalRouteHits: safeInt(rateLimitResult?.events?.criticalRouteHits, 0)
    }
  };
}

function normalizeFreshnessResult(freshnessResult = null) {
  if (!freshnessResult || typeof freshnessResult !== "object") return null;

  return {
    ok: Boolean(freshnessResult.ok),
    code: safeString(freshnessResult.code || "", 100),
    ageMs: safeNumber(freshnessResult.ageMs, 0),
    degraded: freshnessResult.degraded === true,
    events: {
      freshnessSignals: safeInt(freshnessResult?.events?.freshnessSignals, 0),
      replaySignals: safeInt(freshnessResult?.events?.replaySignals, 0)
    }
  };
}

function normalizeThreatResult(threatResult = null) {
  if (!threatResult || typeof threatResult !== "object") return null;

  return {
    threatScore: safeInt(threatResult.threatScore, 0, 0, 100),
    level: normalizeLevel(threatResult.level),
    action: normalizeAction(threatResult.action),
    signals: {
      replayPressure: safeInt(threatResult?.signals?.replayPressure, 0, 0, 100),
      coordinatedPressure: safeInt(threatResult?.signals?.coordinatedPressure, 0, 0, 100),
      exploitPressure: safeInt(threatResult?.signals?.exploitPressure, 0, 0, 100),
      breachPressure: safeInt(threatResult?.signals?.breachPressure, 0, 0, 100)
    },
    events: {
      botEvents: safeInt(threatResult?.events?.botEvents, 0),
      abuseEvents: safeInt(threatResult?.events?.abuseEvents, 0),
      rateLimitEvents: safeInt(threatResult?.events?.rateLimitEvents, 0),
      freshnessFailures: safeInt(threatResult?.events?.freshnessFailures, 0),
      blockEvents: safeInt(threatResult?.events?.blockEvents, 0),
      hardBlockSignals: safeInt(threatResult?.events?.hardBlockSignals, 0),
      criticalRouteHits: safeInt(threatResult?.events?.criticalRouteHits, 0),
      exploitSignals: safeInt(threatResult?.events?.exploitSignals, 0),
      breachSignals: safeInt(threatResult?.events?.breachSignals, 0),
      endpointSpread: safeInt(threatResult?.events?.endpointSpread, 0)
    }
  };
}

function normalizePayloadThreatResult(payloadThreatResult = null) {
  if (!payloadThreatResult || typeof payloadThreatResult !== "object") return null;

  return {
    threatScore: safeInt(payloadThreatResult.threatScore, 0, 0, 100),
    reasons: normalizeArrayReasons(payloadThreatResult.reasons),
    events: {
      exploitSignals: safeInt(payloadThreatResult?.events?.exploitSignals, 0),
      breachSignals: safeInt(payloadThreatResult?.events?.breachSignals, 0),
      malformedSignals: safeInt(payloadThreatResult?.events?.malformedSignals, 0),
      methodSignals: safeInt(payloadThreatResult?.events?.methodSignals, 0)
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
    successfulAuthCount: safeInt(securityState.successfulAuthCount, 0),
    exploitFlagCount: safeInt(securityState.exploitFlagCount, 0),
    breachFlagCount: safeInt(securityState.breachFlagCount, 0),
    replayFlagCount: safeInt(securityState.replayFlagCount, 0),
    coordinatedFlagCount: safeInt(securityState.coordinatedFlagCount, 0)
  };
}

export function evaluateRisk(inputs = {}) {
  const botResult = normalizeBotResult(inputs.botResult);
  const abuseResult = normalizeAbuseResult(inputs.abuseResult);
  const rateLimitResult = normalizeRateLimitResult(inputs.rateLimitResult);
  const freshnessResult = normalizeFreshnessResult(inputs.freshnessResult);
  const threatResult = normalizeThreatResult(inputs.threatResult);
  const payloadThreatResult = normalizePayloadThreatResult(inputs.payloadThreatResult);
  const securityState = normalizeSecurityState(inputs.securityState);
  const routeSensitivity = normalizeRouteSensitivity(
    inputs.routeSensitivity || "normal"
  );

  const state = {
    score: 0,
    reasons: [],
    hardBlockSignals: 0,
    criticalSignals: 0,
    degradedSignals: 0,
    pressures: createPressureBreakdown(),
    events: createEventSignals()
  };

  /* ROUTE SENSITIVITY */
  if (routeSensitivity === "critical") {
    addWeightedScore(state, 8, "route:critical", "routePressure");
  }
  if (routeSensitivity === "high") {
    addWeightedScore(state, 4, "route:high", "routePressure");
  }

  /* BOT SIGNALS */
  if (botResult) {
    if (botResult.riskScore >= 70) addWeightedScore(state, 20, "bot:high_risk", "botPressure");
    else if (botResult.riskScore >= 40) addWeightedScore(state, 10, "bot:medium_risk", "botPressure");

    if (botResult.escalatedAction === "block")
      addWeightedScore(state, 20, "bot:escalated_block", "botPressure");

    if (botResult.escalatedAction === "challenge")
      addWeightedScore(state, 10, "bot:escalated_challenge", "botPressure");

    if (botResult.telemetryQualityScore <= 30)
      addWeightedScore(state, 10, "bot:low_telemetry_quality", "botPressure");

    if (botResult.distributed.suspicionScore >= 120)
      addWeightedScore(state, 25, "bot:distributed_suspicion_high", "botPressure");
    else if (botResult.distributed.suspicionScore >= 60)
      addWeightedScore(state, 12, "bot:distributed_suspicion_medium", "botPressure");

    if (botResult.distributed.recentHardBlocks >= 2)
      addWeightedScore(state, 15, "bot:recent_hard_blocks", "botPressure");

    if (botResult.distributed.recentChallenges >= 3)
      addWeightedScore(state, 8, "bot:recent_challenges", "botPressure");

    if (botResult.distributed.sensitiveRouteHits >= 5)
      addWeightedScore(state, 10, "bot:sensitive_route_targeting", "botPressure");

    if (botResult.distributed.uniqueRecentRoutes >= 4) {
      addWeightedScore(state, 10, "bot:route_spread", "botPressure");
      state.events.coordinatedSignals += 1;
    }

    if (botResult.hardBlockSignals > 0) {
      state.hardBlockSignals += botResult.hardBlockSignals;
      addWeightedScore(state, 35, "bot:hard_block_signal", "botPressure");
    }

    if (botResult.distributed.hardBlockCount >= 2) {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 20, "bot:distributed_hard_block_history", "botPressure");
    }

    for (const reason of botResult.reasons) {
      pushReason(state.reasons, `bot:${reason}`);
    }
  }

  /* ABUSE */
  if (abuseResult) {
    if (abuseResult.abuseScore >= 70)
      addWeightedScore(state, 22, "abuse:high_score", "abusePressure");
    else if (abuseResult.abuseScore >= 40)
      addWeightedScore(state, 10, "abuse:medium_score", "abusePressure");

    if (abuseResult.penaltyActive)
      addWeightedScore(state, 18, "abuse:penalty_active", "abusePressure");

    if (abuseResult.snapshot.weightedFailures >= 12)
      addWeightedScore(state, 15, "abuse:heavy_failures", "abusePressure");

    if (abuseResult.snapshot.uniqueRoutes >= 4) {
      addWeightedScore(state, 10, "abuse:multi_route_probing", "abusePressure");
      state.events.coordinatedSignals += 1;
    }

    if (abuseResult.snapshot.criticalRouteTouchesRecent >= 2)
      addWeightedScore(state, 20, "abuse:critical_route_targeting", "abusePressure");

    if (abuseResult.snapshot.coordinatedProbe) {
      addWeightedScore(state, 15, "abuse:coordinated_probe", "abusePressure");
      state.events.coordinatedSignals += 1;
    }

    if (abuseResult.snapshot.breachLikePattern) {
      state.criticalSignals += 1;
      state.events.breachSignals += 1;
      addWeightedScore(state, 25, "abuse:breach_like_pattern", "abusePressure");
    }

    if (abuseResult.events.breachSignals > 0) {
      state.criticalSignals += 1;
      state.hardBlockSignals += 1;
      state.events.breachSignals += 1;
      addWeightedScore(state, 30, "abuse:breach_signal", "abusePressure");
    }

    if (abuseResult.events.hardBlockSignals > 0) {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 15, "abuse:hard_block_signal", "abusePressure");
    }

    if (abuseResult.events.endpointSpread >= 4) {
      addWeightedScore(state, 12, "abuse:endpoint_spread", "abusePressure");
      state.events.coordinatedSignals += 1;
    }

    for (const reason of abuseResult.reasons) {
      pushReason(state.reasons, `abuse:${reason}`);
    }
  }

  /* RATE LIMIT */
  if (rateLimitResult) {
    if (rateLimitResult.degraded === true) {
      state.degradedSignals += 1;
      addWeightedScore(state, 5, "rate:degraded", "ratePressure");
    }

    if (!rateLimitResult.allowed)
      addWeightedScore(state, 15, "rate:limit_exceeded", "ratePressure");

    if (rateLimitResult.penaltyActive)
      addWeightedScore(state, 15, "rate:penalty_active", "ratePressure");

    if (rateLimitResult.violations >= 4)
      addWeightedScore(state, 18, "rate:repeat_violations", "ratePressure");

    if (rateLimitResult.burstCount >= 10)
      addWeightedScore(state, 15, "rate:burst_pattern", "ratePressure");

    if (rateLimitResult.routeSensitivity === "critical")
      addWeightedScore(state, 10, "rate:critical_route_pressure", "ratePressure");

    if (rateLimitResult.events.burstSignals > 0) {
      addWeightedScore(state, 10, "rate:burst_signal", "ratePressure");
      state.events.coordinatedSignals += 1;
    }

    if (rateLimitResult.events.hardBlockSignals > 0) {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 12, "rate:hard_block_signal", "ratePressure");
    }
  }

  /* REQUEST FRESHNESS */
  if (freshnessResult) {
    if (freshnessResult.degraded === true) {
      state.degradedSignals += 1;
      addWeightedScore(state, 5, "freshness:degraded", "freshnessPressure");
    }
  }

  if (freshnessResult && !freshnessResult.ok) {
    addWeightedScore(
      state,
      20,
      `freshness:${freshnessResult.code || "failed"}`,
      "freshnessPressure"
    );

    if (
      freshnessResult.code === "replayed_nonce" ||
      freshnessResult.code === "future_request_timestamp"
    ) {
      state.hardBlockSignals += 1;
      state.events.replaySignals += 1;
      state.criticalSignals += routeSensitivity === "critical" ? 1 : 0;
    }

    if (freshnessResult.events.replaySignals > 0) {
      state.hardBlockSignals += 1;
      state.events.replaySignals += 1;
      addWeightedScore(state, 15, "freshness:replay_signal", "freshnessPressure");
    }
  }

  /* PAYLOAD THREATS */
  if (payloadThreatResult) {
    if (payloadThreatResult.threatScore >= 70)
      addWeightedScore(state, 25, "payload:high_threat", "payloadPressure");
    else if (payloadThreatResult.threatScore >= 40)
      addWeightedScore(state, 12, "payload:medium_threat", "payloadPressure");

    if (payloadThreatResult.events.exploitSignals > 0) {
      state.criticalSignals += 1;
      state.events.exploitSignals += 1;
      addWeightedScore(state, 28, "payload:exploit_signal", "payloadPressure");
    }

    if (payloadThreatResult.events.breachSignals > 0) {
      state.hardBlockSignals += 1;
      state.criticalSignals += 1;
      state.events.breachSignals += 1;
      addWeightedScore(state, 35, "payload:breach_signal", "payloadPressure");
    }

    if (payloadThreatResult.events.methodSignals > 0)
      addWeightedScore(state, 10, "payload:invalid_method_pressure", "payloadPressure");

    for (const reason of payloadThreatResult.reasons) {
      pushReason(state.reasons, `payload:${reason}`);
    }
  }

  /* THREAT MEMORY */
  if (threatResult) {
    if (threatResult.threatScore >= 80)
      addWeightedScore(state, 25, "memory:high", "memoryPressure");
    else if (threatResult.threatScore >= 50)
      addWeightedScore(state, 12, "memory:medium", "memoryPressure");

    if (threatResult.events.blockEvents >= 3)
      addWeightedScore(state, 12, "memory:repeat_block_events", "memoryPressure");

    if (threatResult.events.hardBlockSignals >= 2) {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 15, "memory:hard_block_signals", "memoryPressure");
    }

    if (threatResult.events.exploitSignals > 0) {
      state.criticalSignals += 1;
      state.events.exploitSignals += 1;
      addWeightedScore(state, 18, "memory:exploit_signals", "memoryPressure");
    }

    if (threatResult.events.breachSignals > 0) {
      state.criticalSignals += 1;
      state.hardBlockSignals += 1;
      state.events.breachSignals += 1;
      addWeightedScore(state, 22, "memory:breach_signals", "memoryPressure");
    }

    if (
      threatResult.events.endpointSpread >= 4 ||
      safeInt(threatResult?.signals?.coordinatedPressure, 0, 0, 100) > 0
    ) {
      addWeightedScore(state, 10, "memory:endpoint_spread", "memoryPressure");
      state.events.coordinatedSignals += 1;
    }

    if (safeInt(threatResult?.signals?.replayPressure, 0, 0, 100) > 0) {
      state.events.replaySignals += 1;
    }
  }

  /* SECURITY STATE */
  if (securityState) {
    if (securityState.currentRiskScore >= 75)
      addWeightedScore(state, 20, "state:high_risk_score", "statePressure");

    if (securityState.lockoutCount >= 2)
      addWeightedScore(state, 18, "state:lockout_history", "statePressure");

    if (securityState.currentRiskLevel === "critical") {
      state.hardBlockSignals += 1;
      addWeightedScore(state, 15, "state:critical_risk_level", "statePressure");
    }

    if (securityState.exploitFlagCount >= 1) {
      state.criticalSignals += 1;
      state.events.exploitSignals += 1;
      addWeightedScore(state, 20, "state:exploit_flag_history", "statePressure");
    }

    if (securityState.breachFlagCount >= 1) {
      state.criticalSignals += 1;
      state.hardBlockSignals += 1;
      state.events.breachSignals += 1;
      addWeightedScore(state, 25, "state:breach_flag_history", "statePressure");
    }

    if (securityState.replayFlagCount >= 1) {
      state.events.replaySignals += 1;
      addWeightedScore(state, 10, "state:replay_flag_history", "statePressure");
    }

    if (securityState.coordinatedFlagCount >= 1) {
      state.events.coordinatedSignals += 1;
      addWeightedScore(state, 12, "state:coordinated_flag_history", "statePressure");
    }
  }

  /* FINALIZE */
  state.score = Math.min(100, safeInt(state.score, 0, 0, 100));
  state.reasons = state.reasons.slice(0, MAX_REASONS);

  state.events.exploitSignals = safeInt(state.events.exploitSignals, 0, 0, 100);
  state.events.breachSignals = safeInt(state.events.breachSignals, 0, 0, 100);
  state.events.replaySignals = safeInt(state.events.replaySignals, 0, 0, 100);
  state.events.coordinatedSignals = safeInt(state.events.coordinatedSignals, 0, 0, 100);

  const level = getLevel(state.score);
  const action = getAction(
    state.score,
    state.hardBlockSignals,
    state.criticalSignals,
    state.events
  );

  const criticalAttackLikely =
    level === "critical" ||
    state.events.breachSignals > 0 ||
    (state.events.exploitSignals > 0 && state.hardBlockSignals > 0) ||
    state.criticalSignals >= 2 ||
    state.hardBlockSignals >= 2;

  let containmentAction = "none";

  if (action === "block") {
    if (state.events.breachSignals > 0) {
      containmentAction = "temporary_containment";
    } else if (
      state.events.exploitSignals > 0 ||
      criticalAttackLikely
    ) {
      containmentAction = "freeze_sensitive_route";
    } else {
      containmentAction = level === "critical"
        ? "freeze_sensitive_route"
        : "temporary_containment";
    }
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
    criticalSignals: safeInt(state.criticalSignals, 0, 0, 100),
    criticalAttackLikely,
    degraded: state.degradedSignals > 0,
    reasons: state.reasons,
    pressures: {
      routePressure: safeInt(state.pressures.routePressure, 0, 0, 100),
      botPressure: safeInt(state.pressures.botPressure, 0, 0, 100),
      abusePressure: safeInt(state.pressures.abusePressure, 0, 0, 100),
      ratePressure: safeInt(state.pressures.ratePressure, 0, 0, 100),
      freshnessPressure: safeInt(state.pressures.freshnessPressure, 0, 0, 100),
      payloadPressure: safeInt(state.pressures.payloadPressure, 0, 0, 100),
      memoryPressure: safeInt(state.pressures.memoryPressure, 0, 0, 100),
      statePressure: safeInt(state.pressures.statePressure, 0, 0, 100)
    },
    events: state.events
  };
}
