import { createActorContext } from "./_actor-context.js";
import { evaluateRisk } from "./_risk-engine.js";

import { trackBotBehavior } from "./_bot-detection.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";
import { checkApiRateLimit } from "./_rate-limit.js";
import { validateFreshRequest } from "./_request-freshness.js";
import { evaluateThreat } from "./_threat-intelligence.js";
import { evaluateContainment } from "./_security-containment.js";
import { evaluateAdaptiveThreatMode } from "./_adaptive-threat-mode.js";

function safeString(value, maxLength = 200) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeBoolean(value) {
  return value === true;
}

function normalizeAction(value = "allow") {
  const normalized = safeString(value || "allow", 20).toLowerCase();
  if (normalized === "block" || normalized === "challenge" || normalized === "throttle") {
    return normalized;
  }
  return "allow";
}

function getRequestTimestamp(body = {}) {
  const candidates = [
    body?.requestAt,
    body?.eventAt,
    body?.timestamp
  ];

  for (const value of candidates) {
    const num = Number(value);
    if (Number.isFinite(num) && num > 0) {
      return num;
    }
  }

  return 0;
}

function pickFinalAction({
  containment,
  risk,
  rateLimitResult,
  adaptiveModeResult
}) {
  const riskAction = normalizeAction(risk?.action || "allow");
  const containmentAction = normalizeAction(containment?.action || "allow");
  const rateLimitAction = normalizeAction(rateLimitResult?.recommendedAction || "allow");
  const adaptiveMode = safeString(adaptiveModeResult?.mode || "normal", 20).toLowerCase();

  if (containment?.blocked) {
    return "block";
  }

  if (adaptiveMode === "lockdown") {
    return "block";
  }

  if (riskAction === "block") {
    return "block";
  }

  if (rateLimitResult && !rateLimitResult.allowed) {
    if (rateLimitAction === "block") return "block";
    if (rateLimitAction === "challenge") return "challenge";
    if (rateLimitAction === "throttle") return "throttle";
  }

  if (containmentAction === "challenge" && riskAction === "allow") {
    return "challenge";
  }

  if (adaptiveMode === "defense" && riskAction === "allow") {
    return "challenge";
  }

  if (adaptiveMode === "elevated" && riskAction === "allow") {
    return "throttle";
  }

  if (riskAction === "challenge") {
    return "challenge";
  }

  if (riskAction === "throttle") {
    return "throttle";
  }

  return "allow";
}

function pickFinalContainmentAction({
  containment,
  risk,
  adaptiveModeResult
}) {
  if (containment?.blocked) {
    return "temporary_containment";
  }

  if (containment?.action === "challenge") {
    return "step_up_verification";
  }

  if (adaptiveModeResult?.mode === "lockdown") {
    return "temporary_containment";
  }

  if (adaptiveModeResult?.mode === "defense") {
    return "step_up_verification";
  }

  if (adaptiveModeResult?.mode === "elevated" && risk?.containmentAction === "none") {
    return "slow_down_actor";
  }

  return safeString(risk?.containmentAction || "none", 50);
}

function buildSafeSignalBundle({
  botResult = null,
  abuseResult = null,
  rateLimitResult = null,
  freshnessResult = null,
  threatResult = null,
  containmentResult = null,
  adaptiveModeResult = null
} = {}) {
  return {
    botResult: botResult || null,
    abuseResult: abuseResult || null,
    rateLimitResult: rateLimitResult || null,
    freshnessResult: freshnessResult || null,
    threatResult: threatResult || null,
    containmentResult: containmentResult || null,
    adaptiveModeResult: adaptiveModeResult || null
  };
}

export async function runSecurityOrchestrator({
  req = null,
  body = {},
  behavior = {},
  context = {},
  route = "",
  rateLimitConfig = null,
  freshnessConfig = null,
  abuseSuccess = true,
  containmentConfig = {}
} = {}) {
  const actor = createActorContext({
    req,
    body,
    behavior,
    context,
    route
  });

  let botResult = null;

  try {
    botResult = await trackBotBehavior(behavior, req, {
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId
    });
  } catch (error) {
    console.error("Bot detection failed:", error);
  }

  let abuseResult = null;

  try {
    abuseResult = await trackApiAbuse({
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId,
      route: actor.route,
      success: safeBoolean(abuseSuccess) ? true : false
    });
  } catch (error) {
    console.error("Abuse analysis failed:", error);
  }

  let rateLimitResult = null;

  if (rateLimitConfig) {
    try {
      rateLimitResult = await checkApiRateLimit({
        key: safeString(rateLimitConfig.key || actor.actorKey, 200),
        route: actor.route,
        limit: Number(rateLimitConfig.limit),
        windowMs: Number(rateLimitConfig.windowMs)
      });
    } catch (error) {
      console.error("Rate limit failed:", error);
    }
  }

  let freshnessResult = null;

  if (freshnessConfig) {
    try {
      freshnessResult = await validateFreshRequest({
        requestAt: getRequestTimestamp(body),
        nonce: safeString(body.nonce || "", 200),
        scope: safeString(freshnessConfig.scope || actor.route, 100),
        requireNonce: safeBoolean(freshnessConfig.requireNonce),
        maxAgeMs: Number(freshnessConfig.maxAgeMs),
        futureToleranceMs: Number(freshnessConfig.futureToleranceMs),
        nonceTtlMs: Number(freshnessConfig.nonceTtlMs)
      });
    } catch (error) {
      console.error("Freshness check failed:", error);
    }
  }

  let threatResult = null;

  try {
    threatResult = await evaluateThreat({
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId,
      route: actor.route,
      botResult,
      abuseResult,
      rateLimitResult,
      freshnessResult
    });
  } catch (error) {
    console.error("Threat intelligence failed:", error);
  }

  const risk = evaluateRisk({
    botResult,
    abuseResult,
    rateLimitResult,
    freshnessResult,
    threatResult
  });

  let containmentResult = null;

  try {
    containmentResult = await evaluateContainment({
      route: actor.route,
      isAdminRoute: safeBoolean(containmentConfig.isAdminRoute),
      isWriteAction: safeBoolean(containmentConfig.isWriteAction),
      actionType: safeString(containmentConfig.actionType || "", 50)
    });
  } catch (error) {
    console.error("Containment evaluation failed:", error);
  }

  let adaptiveModeResult = null;

  try {
    adaptiveModeResult = await evaluateAdaptiveThreatMode({
      risk,
      threatResult,
      abuseResult,
      botResult
    });
  } catch (error) {
    console.error("Adaptive threat mode evaluation failed:", error);
  }

  const finalAction = pickFinalAction({
    containment: containmentResult,
    risk,
    rateLimitResult,
    adaptiveModeResult
  });

  const finalContainmentAction = pickFinalContainmentAction({
    containment: containmentResult,
    risk,
    adaptiveModeResult
  });

  return {
    actor,
    risk: {
      ...risk,
      finalAction,
      finalContainmentAction
    },
    signals: buildSafeSignalBundle({
      botResult,
      abuseResult,
      rateLimitResult,
      freshnessResult,
      threatResult,
      containmentResult,
      adaptiveModeResult
    })
  };
}
