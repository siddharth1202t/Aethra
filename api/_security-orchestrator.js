import { createActorContext } from "./_actor-context.js";
import { evaluateRisk } from "./_risk-engine.js";

import { analyzeBotBehavior } from "./_bot-detection.js";
import { analyzeApiAbuse } from "./_api-abuse-protection.js";
import { checkRateLimit } from "./_rate-limit.js";
import { validateFreshRequest } from "./_request-freshness.js";
import { analyzeThreatIntelligence } from "./_threat-intelligence.js";

function safeString(value, maxLength = 200) {
  return String(value || "").slice(0, maxLength);
}

export async function runSecurityOrchestrator({
  req = null,
  body = {},
  behavior = {},
  context = {},
  route = "",
  rateLimitConfig = null,
  freshnessConfig = null
} = {}) {

  const actor = createActorContext({
    req,
    body,
    behavior,
    context,
    route
  });

  /* ---------------- BOT ANALYSIS ---------------- */

  let botResult = null;

  try {
    botResult = analyzeBotBehavior(behavior, req);
  } catch (error) {
    console.error("Bot detection failed:", error);
  }

  /* ---------------- ABUSE ANALYSIS ---------------- */

  let abuseResult = null;

  try {
    abuseResult = await analyzeApiAbuse({
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId,
      route: actor.route
    });
  } catch (error) {
    console.error("Abuse analysis failed:", error);
  }

  /* ---------------- RATE LIMIT ---------------- */

  let rateLimitResult = null;

  if (rateLimitConfig) {
    try {
      rateLimitResult = await checkRateLimit({
        key: rateLimitConfig.key || actor.actorKey,
        route: actor.route,
        ip: actor.ip,
        limit: rateLimitConfig.limit,
        windowMs: rateLimitConfig.windowMs
      });
    } catch (error) {
      console.error("Rate limit failed:", error);
    }
  }

  /* ---------------- FRESHNESS ---------------- */

  let freshnessResult = null;

  if (freshnessConfig) {
    try {
      freshnessResult = await validateFreshRequest({
        requestAt: body.requestAt,
        nonce: safeString(body.nonce || "", 200),
        scope: freshnessConfig.scope || actor.route,
        requireNonce: freshnessConfig.requireNonce || false
      });
    } catch (error) {
      console.error("Freshness check failed:", error);
    }
  }

  /* ---------------- THREAT MEMORY ---------------- */

  let threatResult = null;

  try {
    threatResult = await analyzeThreatIntelligence({
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId,
      route: actor.route
    });
  } catch (error) {
    console.error("Threat intelligence failed:", error);
  }

  /* ---------------- RISK ENGINE ---------------- */

  const risk = evaluateRisk({
    botResult,
    abuseResult,
    rateLimitResult,
    freshnessResult,
    threatResult
  });

  /* ---------------- FINAL RESPONSE ---------------- */

  return {
    actor,

    risk,

    signals: {
      botResult,
      abuseResult,
      rateLimitResult,
      freshnessResult,
      threatResult
    }
  };
}
