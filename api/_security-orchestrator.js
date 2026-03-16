import { createActorContext } from "./_actor-context.js";
import { evaluateRisk } from "./_risk-engine.js";

import { trackBotBehavior } from "./_bot-detection.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";
import { checkApiRateLimit } from "./_rate-limit.js";
import { validateFreshRequest } from "./_request-freshness.js";
import { evaluateThreat } from "./_threat-intelligence.js";
import { evaluateContainment } from "./_security-containment.js";

function safeString(value, maxLength = 200) {
  return String(value || "").slice(0, maxLength);
}

function pickFinalAction({ containment, risk, rateLimitResult }) {
  if (containment?.blocked) {
    return "block";
  }

  if (risk?.action === "block") {
    return "block";
  }

  if (rateLimitResult && !rateLimitResult.allowed) {
    if (rateLimitResult.recommendedAction === "block") return "block";
    if (rateLimitResult.recommendedAction === "challenge") return "challenge";
    if (rateLimitResult.recommendedAction === "throttle") return "throttle";
  }

  if (containment?.action === "challenge" && risk?.action === "allow") {
    return "challenge";
  }

  if (risk?.action === "challenge") {
    return "challenge";
  }

  if (risk?.action === "throttle") {
    return "throttle";
  }

  return "allow";
}

function pickFinalContainmentAction({ containment, risk }) {
  if (containment?.blocked) {
    return containment.reason || "containment_blocked";
  }

  if (containment?.action === "challenge") {
    return containment.reason || "containment_challenge";
  }

  return risk?.containmentAction || "none";
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
      success: abuseSuccess
    });
  } catch (error) {
    console.error("Abuse analysis failed:", error);
  }

  let rateLimitResult = null;

  if (rateLimitConfig) {
    try {
      rateLimitResult = await checkApiRateLimit({
        key: rateLimitConfig.key || actor.actorKey,
        route: actor.route,
        limit: rateLimitConfig.limit,
        windowMs: rateLimitConfig.windowMs
      });
    } catch (error) {
      console.error("Rate limit failed:", error);
    }
  }

  let freshnessResult = null;

  if (freshnessConfig) {
    try {
      freshnessResult = await validateFreshRequest({
        requestAt: body.requestAt,
        nonce: safeString(body.nonce || "", 200),
        scope: freshnessConfig.scope || actor.route,
        requireNonce: Boolean(freshnessConfig.requireNonce),
        maxAgeMs: freshnessConfig.maxAgeMs,
        futureToleranceMs: freshnessConfig.futureToleranceMs,
        nonceTtlMs: freshnessConfig.nonceTtlMs
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
      isAdminRoute: Boolean(containmentConfig.isAdminRoute),
      isWriteAction: Boolean(containmentConfig.isWriteAction),
      actionType: safeString(containmentConfig.actionType || "", 50)
    });
  } catch (error) {
    console.error("Containment evaluation failed:", error);
  }

  const finalAction = pickFinalAction({
    containment: containmentResult,
    risk,
    rateLimitResult
  });

  const finalContainmentAction = pickFinalContainmentAction({
    containment: containmentResult,
    risk
  });

  return {
    actor,
    risk: {
      ...risk,
      finalAction,
      finalContainmentAction
    },
    signals: {
      botResult,
      abuseResult,
      rateLimitResult,
      freshnessResult,
      threatResult,
      containmentResult
    }
  };
}
