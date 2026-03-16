const MAX_REASON_LENGTH = 100;
const MAX_REASONS = 50;

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
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

function getAction(score, hasHardBlock = false) {
  if (hasHardBlock || score >= 95) return "block";
  if (score >= 75) return "challenge";
  if (score >= 45) return "throttle";
  return "allow";
}

function normalizeBotResult(botResult = null) {
  if (!botResult || typeof botResult !== "object") return null;

  return {
    riskScore: safeInt(botResult.riskScore, 0, 0, 100),
    level: safeString(botResult.level || "low", 20),
    recommendedAction: safeString(botResult.recommendedAction || "allow", 20),
    escalatedAction: safeString(botResult.escalatedAction || "allow", 20),
    telemetryQualityScore: safeInt(botResult.telemetryQualityScore, 100, 0, 100),
    hardBlockSignals: safeInt(botResult.hardBlockSignals, 0, 0, 20),
    distributed: {
      suspicionScore: safeInt(botResult?.distributed?.suspicionScore, 0, 0, 1000),
      hardBlockCount: safeInt(botResult?.distributed?.hardBlockCount, 0, 0, 1000),
      suspiciousCount: safeInt(botResult?.distributed?.suspiciousCount, 0, 0, 100000),
      sensitiveRouteHits: safeInt(botResult?.distributed?.sensitiveRouteHits, 0, 0, 100000)
    },
    reasons: Array.isArray(botResult.reasons) ? botResult.reasons.slice(0, 20) : []
  };
}

function normalizeAbuseResult(abuseResult = null) {
  if (!abuseResult || typeof abuseResult !== "object") return null;

  return {
    abuseScore: safeInt(abuseResult.abuseScore, 0, 0, 100),
    level: safeString(abuseResult.level || "low", 20),
    recommendedAction: safeString(abuseResult.recommendedAction || "allow", 20),
    containmentAction: safeString(abuseResult.containmentAction || "none", 40),
    penaltyActive: Boolean(abuseResult.penaltyActive),
    snapshot: {
      weightedRequests: safeInt(abuseResult?.snapshot?.weightedRequests, 0, 0, 100000),
      weightedFailures: safeInt(abuseResult?.snapshot?.weightedFailures, 0, 0, 100000),
      uniqueRoutes: safeInt(abuseResult?.snapshot?.uniqueRoutes, 0, 0, 100000),
      burstCount: safeInt(abuseResult?.snapshot?.burstCount, 0, 0, 100000),
      criticalRouteTouchesRecent: safeInt(
        abuseResult?.snapshot?.criticalRouteTouchesRecent,
        0,
        0,
        100000
      ),
      suspiciousEvents: safeInt(abuseResult?.snapshot?.suspiciousEvents, 0, 0, 100000),
      penaltyCount: safeInt(abuseResult?.snapshot?.penaltyCount, 0, 0, 100000)
    },
    reasons: Array.isArray(abuseResult.reasons) ? abuseResult.reasons.slice(0, 20) : []
  };
}

function normalizeRateLimitResult(rateLimitResult = null) {
  if (!rateLimitResult || typeof rateLimitResult !== "object") return null;

  return {
    allowed: Boolean(rateLimitResult.allowed),
    recommendedAction: safeString(rateLimitResult.recommendedAction || "allow", 20),
    containmentAction: safeString(rateLimitResult.containmentAction || "none", 40),
    penaltyActive: Boolean(rateLimitResult.penaltyActive),
    overBy: safeInt(rateLimitResult.overBy, 0, 0, 100000),
    violations: safeInt(rateLimitResult.violations, 0, 0, 100000),
    burstCount: safeInt(rateLimitResult.burstCount, 0, 0, 100000),
    routeSensitivity: safeString(rateLimitResult.routeSensitivity || "normal", 20),
    highestCountSeen: safeInt(rateLimitResult.highestCountSeen, 0, 0, 100000)
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
    level: safeString(threatResult.level || "low", 20),
    action: safeString(threatResult.action || "allow", 20),
    events: {
      botEvents: safeInt(threatResult?.events?.botEvents, 0, 0, 100000),
      abuseEvents: safeInt(threatResult?.events?.abuseEvents, 0, 0, 100000),
      rateLimitEvents: safeInt(threatResult?.events?.rateLimitEvents, 0, 0, 100000),
      freshnessFailures: safeInt(threatResult?.events?.freshnessFailures, 0, 0, 100000)
    }
  };
}

export function evaluateRisk(inputs = {}) {
  const botResult = normalizeBotResult(inputs.botResult);
  const abuseResult = normalizeAbuseResult(inputs.abuseResult);
  const rateLimitResult = normalizeRateLimitResult(inputs.rateLimitResult);
  const freshnessResult = normalizeFreshnessResult(inputs.freshnessResult);
  const threatResult = normalizeThreatResult(inputs.threatResult);

  const state = {
    score: 0,
    reasons: [],
    hardBlockSignals: 0
  };

  if (botResult) {
    if (botResult.riskScore >= 70) addWeightedScore(state, 20, "bot_high_risk");
    else if (botResult.riskScore >= 40) addWeightedScore(state, 10, "bot_medium_risk");

    if (botResult.telemetryQualityScore <= 30) {
      addWeightedScore(state, 10, "bot_low_telemetry_quality");
    }

    if (botResult.distributed.suspicionScore >= 120) {
      addWeightedScore(state, 25, "bot_distributed_suspicion_high");
    } else if (botResult.distributed.suspicionScore >= 60) {
      addWeightedScore(state, 12, "bot_distributed_suspicion_medium");
    }

    if (botResult.distributed.sensitiveRouteHits >= 5) {
      addWeightedScore(state, 10, "bot_sensitive_route_targeting");
    }

    if (botResult.hardBlockSignals > 0) {
      state.hardBlockSignals += botResult.hardBlockSignals;
      addWeightedScore(state, 35, "bot_hard_block_signal");
    }

    for (const reason of botResult.reasons) {
      pushReason(state.reasons, `bot:${safeString(reason, 80)}`);
    }
  }

  if (abuseResult) {
    if (abuseResult.abuseScore >= 70) addWeightedScore(state, 22, "abuse_high_score");
    else if (abuseResult.abuseScore >= 40) addWeightedScore(state, 10, "abuse_medium_score");

    if (abuseResult.penaltyActive) {
      addWeightedScore(state, 18, "abuse_penalty_active");
    }

    if (abuseResult.snapshot.weightedFailures >= 12) {
      addWeightedScore(state, 15, "abuse_heavy_failures");
    } else if (abuseResult.snapshot.weightedFailures >= 6) {
      addWeightedScore(state, 8, "abuse_repeated_failures");
    }

    if (abuseResult.snapshot.uniqueRoutes >= 4) {
      addWeightedScore(state, 10, "abuse_multi_route_probing");
    }

    if (abuseResult.snapshot.criticalRouteTouchesRecent >= 2) {
      addWeightedScore(state, 20, "abuse_critical_route_targeting");
    }

    for (const reason of abuseResult.reasons) {
      pushReason(state.reasons, `abuse:${safeString(reason, 80)}`);
    }
  }

  if (rateLimitResult) {
    if (!rateLimitResult.allowed) {
      addWeightedScore(state, 15, "rate_limit_exceeded");
    }

    if (rateLimitResult.penaltyActive) {
      addWeightedScore(state, 15, "rate_limit_penalty_active");
    }

    if (rateLimitResult.violations >= 4) {
      addWeightedScore(state, 18, "rate_limit_repeat_violations");
    } else if (rateLimitResult.violations >= 2) {
      addWeightedScore(state, 8, "rate_limit_multiple_violations");
    }

    if (rateLimitResult.burstCount >= 10) {
      addWeightedScore(state, 15, "rate_limit_burst_pattern");
    }

    if (rateLimitResult.routeSensitivity === "critical") {
      addWeightedScore(state, 10, "rate_limit_critical_route_pressure");
    }
  }

  if (freshnessResult) {
    if (!freshnessResult.ok) {
      addWeightedScore(state, 20, `freshness_${freshnessResult.code || "failed"}`);

      if (
        freshnessResult.code === "replayed_nonce" ||
        freshnessResult.code === "future_request_timestamp"
      ) {
        state.hardBlockSignals += 1;
      }
    }
  }

  if (threatResult) {
    if (threatResult.threatScore >= 80) addWeightedScore(state, 25, "threat_memory_high");
    else if (threatResult.threatScore >= 50) addWeightedScore(state, 12, "threat_memory_medium");

    if (threatResult.events.freshnessFailures >= 3) {
      addWeightedScore(state, 10, "threat_repeat_freshness_failures");
    }

    if (threatResult.events.botEvents >= 5) {
      addWeightedScore(state, 10, "threat_repeat_bot_events");
    }

    if (threatResult.events.abuseEvents >= 5) {
      addWeightedScore(state, 10, "threat_repeat_abuse_events");
    }
  }

  if (botResult && abuseResult) {
    if (botResult.riskScore >= 40 && abuseResult.abuseScore >= 40) {
      addWeightedScore(state, 15, "cross_signal_bot_plus_abuse");
    }

    if (
      botResult.distributed.sensitiveRouteHits >= 5 &&
      abuseResult.snapshot.criticalRouteTouchesRecent >= 2
    ) {
      addWeightedScore(state, 20, "cross_signal_sensitive_route_attack");
    }
  }

  if (abuseResult && rateLimitResult) {
    if (
      abuseResult.snapshot.burstCount >= 8 &&
      rateLimitResult.burstCount >= 8
    ) {
      addWeightedScore(state, 12, "cross_signal_burst_alignment");
    }
  }

  state.score = Math.min(100, safeInt(state.score, 0, 0, 100));
  state.reasons = state.reasons.slice(0, MAX_REASONS);

  const level = getLevel(state.score);
  const action = getAction(state.score, state.hardBlockSignals > 0);

  let containmentAction = "none";

  if (action === "block") {
    containmentAction = level === "critical"
      ? "temporary_containment"
      : "freeze_sensitive_route";
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
    hardBlockSignals: state.hardBlockSignals,
    reasons: state.reasons
  };
}
