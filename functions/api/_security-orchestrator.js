import crypto from "node:crypto";
import { getFirestore } from "firebase-admin/firestore";

import { createActorContext } from "./_actor-context.js";
import { evaluateRisk } from "./_risk-engine.js";
import { trackBotBehavior } from "./_bot-detection.js";
import { trackApiAbuse } from "./_api-abuse-protection.js";
import { checkApiRateLimit } from "./_rate-limit.js";
import { validateFreshRequest } from "./_request-freshness.js";
import { evaluateThreat } from "./_threat-intelligence.js";
import { evaluateContainment } from "./_security-containment.js";
import { evaluateAdaptiveThreatMode } from "./_adaptive-threat-mode.js";
import { getRiskState, updateRiskState } from "./_security-risk-state.js";
import { evaluateAnomalyDetection } from "./_security-anomaly-detection.js";
import { evaluateSecurityAlerts } from "./_security-alerts.js";
import { getRecentSecurityEvents } from "./_security-event-store.js";

function safeString(value, maxLength = 200) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeBoolean(value) {
  return value === true;
}

function safeInt(value, fallback = 0, min = 0, max = 1_000_000) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function normalizeAction(value = "allow") {
  const normalized = safeString(value || "allow", 20).toLowerCase();
  if (
    normalized === "block" ||
    normalized === "challenge" ||
    normalized === "throttle"
  ) {
    return normalized;
  }
  return "allow";
}

function normalizeRouteSensitivity(value = "normal") {
  const normalized = safeString(value || "normal", 20).toLowerCase();
  if (
    normalized === "critical" ||
    normalized === "high" ||
    normalized === "normal"
  ) {
    return normalized;
  }
  return "normal";
}

function getRequestTimestamp(body = {}) {
  const candidates = [body?.requestAt, body?.eventAt, body?.timestamp];

  for (const value of candidates) {
    const num = Number(value);
    if (Number.isFinite(num) && num > 0) {
      return num;
    }
  }

  return 0;
}

function sha256Hex(input = "") {
  try {
    return crypto.createHash("sha256").update(String(input || "")).digest("hex");
  } catch {
    return "";
  }
}

function deriveIpHash(ip = "") {
  const normalizedIp = safeString(ip || "", 100);
  if (!normalizedIp || normalizedIp === "unknown") {
    return "";
  }

  return sha256Hex(normalizedIp).slice(0, 32);
}

function deriveEmailHash(email = "") {
  const normalizedEmail = safeString(email || "", 200).toLowerCase();
  if (!normalizedEmail) {
    return "";
  }

  return sha256Hex(normalizedEmail).slice(0, 64);
}

function buildSafeSignalBundle({
  botResult = null,
  abuseResult = null,
  rateLimitResult = null,
  freshnessResult = null,
  threatResult = null,
  containmentResult = null,
  adaptiveModeResult = null,
  anomalyResult = null,
  securityState = null,
  persistentRiskState = null,
  alertsResult = null
} = {}) {
  return {
    botResult: botResult || null,
    abuseResult: abuseResult || null,
    rateLimitResult: rateLimitResult || null,
    freshnessResult: freshnessResult || null,
    threatResult: threatResult || null,
    containmentResult: containmentResult || null,
    adaptiveModeResult: adaptiveModeResult || null,
    anomalyResult: anomalyResult || null,
    securityState: securityState || null,
    persistentRiskState: persistentRiskState || null,
    alertsResult: alertsResult || null
  };
}

function inferRouteSensitivity(route = "", config = {}) {
  if (config?.routeSensitivity) {
    return normalizeRouteSensitivity(config.routeSensitivity);
  }

  const normalizedRoute = safeString(route || "", 150).toLowerCase();

  if (
    normalizedRoute.includes("login") ||
    normalizedRoute.includes("signup") ||
    normalizedRoute.includes("verify-turnstile") ||
    normalizedRoute.includes("security-log") ||
    normalizedRoute.includes("password") ||
    safeBoolean(config?.isAdminRoute)
  ) {
    return "critical";
  }

  if (
    safeBoolean(config?.isWriteAction) ||
    normalizedRoute.includes("chat") ||
    normalizedRoute.includes("profile")
  ) {
    return "high";
  }

  return "normal";
}

async function readSecurityStateDoc(docId) {
  if (!docId) {
    return null;
  }

  try {
    const db = getFirestore();
    const snap = await db.doc(`securityState/${docId}`).get();
    return snap.exists ? snap.data() || null : null;
  } catch (error) {
    console.error("Security state read failed:", error);
    return null;
  }
}

async function getSecurityStateSummary({
  userId = "",
  email = "",
  ip = "",
  sessionId = ""
} = {}) {
  const safeUserId = safeString(userId || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  const safeSessionId = safeString(sessionId || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  const emailHash = deriveEmailHash(email || "");
  const ipHash = deriveIpHash(ip || "");

  const targets = [
    safeUserId ? `user_${safeUserId}` : "",
    emailHash ? `email_${emailHash}` : "",
    ipHash ? `ip_${ipHash}` : "",
    safeSessionId ? `session_${safeSessionId}` : ""
  ].filter(Boolean);

  if (!targets.length) {
    return null;
  }

  const docs = await Promise.all(targets.map((docId) => readSecurityStateDoc(docId)));

  const merged = {
    currentRiskScore: 0,
    currentRiskLevel: "low",
    failedLoginCount: 0,
    failedSignupCount: 0,
    failedPasswordResetCount: 0,
    captchaFailureCount: 0,
    suspiciousEventCount: 0,
    rateLimitHitCount: 0,
    lockoutCount: 0,
    successfulAuthCount: 0
  };

  for (const doc of docs) {
    if (!doc || typeof doc !== "object") {
      continue;
    }

    merged.currentRiskScore = Math.max(
      merged.currentRiskScore,
      safeInt(doc.currentRiskScore, 0, 0, 100)
    );

    const docRiskLevel = safeString(doc.currentRiskLevel || "", 20).toLowerCase();

    if (docRiskLevel === "critical") {
      merged.currentRiskLevel = "critical";
    } else if (
      merged.currentRiskLevel !== "critical" &&
      docRiskLevel === "high"
    ) {
      merged.currentRiskLevel = "high";
    } else if (
      !["critical", "high"].includes(merged.currentRiskLevel) &&
      docRiskLevel === "medium"
    ) {
      merged.currentRiskLevel = "medium";
    }

    merged.failedLoginCount += safeInt(doc.failedLoginCount, 0, 0, 100000);
    merged.failedSignupCount += safeInt(doc.failedSignupCount, 0, 0, 100000);
    merged.failedPasswordResetCount += safeInt(doc.failedPasswordResetCount, 0, 0, 100000);
    merged.captchaFailureCount += safeInt(doc.captchaFailureCount, 0, 0, 100000);
    merged.suspiciousEventCount += safeInt(doc.suspiciousEventCount, 0, 0, 100000);
    merged.rateLimitHitCount += safeInt(doc.rateLimitHitCount, 0, 0, 100000);
    merged.lockoutCount += safeInt(doc.lockoutCount, 0, 0, 100000);
    merged.successfulAuthCount += safeInt(doc.successfulAuthCount, 0, 0, 100000);
  }

  return merged;
}

function mergeRiskLevel(a = "low", b = "low") {
  const rank = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3
  };

  const safeA = safeString(a || "low", 20).toLowerCase();
  const safeB = safeString(b || "low", 20).toLowerCase();

  return (rank[safeA] || 0) >= (rank[safeB] || 0) ? safeA : safeB;
}

function mergeSecuritySummaries(baseState = null, persistentStates = []) {
  const merged = {
    currentRiskScore: 0,
    currentRiskLevel: "low",
    failedLoginCount: 0,
    failedSignupCount: 0,
    failedPasswordResetCount: 0,
    captchaFailureCount: 0,
    suspiciousEventCount: 0,
    rateLimitHitCount: 0,
    lockoutCount: 0,
    successfulAuthCount: 0
  };

  if (baseState && typeof baseState === "object") {
    merged.currentRiskScore = Math.max(
      merged.currentRiskScore,
      safeInt(baseState.currentRiskScore, 0, 0, 100)
    );
    merged.currentRiskLevel = mergeRiskLevel(
      merged.currentRiskLevel,
      safeString(baseState.currentRiskLevel || "low", 20).toLowerCase()
    );
    merged.failedLoginCount += safeInt(baseState.failedLoginCount, 0, 0, 100000);
    merged.failedSignupCount += safeInt(baseState.failedSignupCount, 0, 0, 100000);
    merged.failedPasswordResetCount += safeInt(baseState.failedPasswordResetCount, 0, 0, 100000);
    merged.captchaFailureCount += safeInt(baseState.captchaFailureCount, 0, 0, 100000);
    merged.suspiciousEventCount += safeInt(baseState.suspiciousEventCount, 0, 0, 100000);
    merged.rateLimitHitCount += safeInt(baseState.rateLimitHitCount, 0, 0, 100000);
    merged.lockoutCount += safeInt(baseState.lockoutCount, 0, 0, 100000);
    merged.successfulAuthCount += safeInt(baseState.successfulAuthCount, 0, 0, 100000);
  }

  for (const state of Array.isArray(persistentStates) ? persistentStates : []) {
    if (!state || typeof state !== "object") {
      continue;
    }

    merged.currentRiskScore = Math.max(
      merged.currentRiskScore,
      safeInt(state.currentRiskScore, 0, 0, 100)
    );
    merged.currentRiskLevel = mergeRiskLevel(
      merged.currentRiskLevel,
      safeString(state.currentRiskLevel || "low", 20).toLowerCase()
    );

    merged.failedLoginCount += safeInt(state.failedLoginCount, 0, 0, 100000);
    merged.failedSignupCount += safeInt(state.failedSignupCount, 0, 0, 100000);
    merged.failedPasswordResetCount += safeInt(state.failedPasswordResetCount, 0, 0, 100000);
    merged.captchaFailureCount += safeInt(state.captchaFailureCount, 0, 0, 100000);
    merged.suspiciousEventCount += safeInt(state.suspiciousEventCount, 0, 0, 100000);
    merged.rateLimitHitCount += safeInt(state.rateLimitHitCount, 0, 0, 100000);
    merged.lockoutCount += safeInt(state.lockoutCount, 0, 0, 100000);
    merged.successfulAuthCount += safeInt(state.successfulAuthCount, 0, 0, 100000);
  }

  return merged;
}

async function getPersistentRiskStates({
  userId = "",
  ip = "",
  sessionId = ""
} = {}) {
  const safeUserId = safeString(userId || "", 128);
  const safeSessionId = safeString(sessionId || "", 128);
  const safeIp = safeString(ip || "", 100);

  const requests = [];

  if (safeSessionId) {
    requests.push(
      getRiskState({
        actorType: "session",
        actorId: safeSessionId
      })
    );
  }

  if (safeUserId) {
    requests.push(
      getRiskState({
        actorType: "user",
        actorId: safeUserId
      })
    );
  }

  if (safeIp && safeIp !== "unknown") {
    requests.push(
      getRiskState({
        actorType: "ip",
        actorId: safeIp
      })
    );
  }

  if (!requests.length) {
    return [];
  }

  try {
    return await Promise.all(requests);
  } catch (error) {
    console.error("Persistent risk state read failed:", error);
    return [];
  }
}

function mergeAnomalyIntoRisk(risk = null, anomalyResult = null) {
  const baseRisk = risk && typeof risk === "object"
    ? { ...risk }
    : {
        riskScore: 0,
        level: "low",
        action: "allow",
        containmentAction: "none",
        hardBlockSignals: 0,
        reasons: []
      };

  if (!anomalyResult || typeof anomalyResult !== "object") {
    return baseRisk;
  }

  const anomalyScore = safeInt(anomalyResult.anomalyScore, 0, 0, 100);
  const anomalyAction = normalizeAction(anomalyResult.action || "allow");
  const anomalyReasons = Array.isArray(anomalyResult.reasons)
    ? anomalyResult.reasons.map((reason) => safeString(reason, 120)).filter(Boolean)
    : [];

  const nextScore = Math.min(
    100,
    safeInt(baseRisk.riskScore, 0, 0, 100) + Math.min(25, Math.floor(anomalyScore / 2))
  );

  const nextReasons = Array.isArray(baseRisk.reasons) ? [...baseRisk.reasons] : [];
  for (const reason of anomalyReasons) {
    if (!nextReasons.includes(reason)) {
      nextReasons.push(reason);
    }
  }

  let nextAction = normalizeAction(baseRisk.action || "allow");
  if (anomalyAction === "block") {
    nextAction = "block";
  } else if (anomalyAction === "challenge" && nextAction !== "block") {
    nextAction = "challenge";
  } else if (
    anomalyAction === "throttle" &&
    nextAction !== "block" &&
    nextAction !== "challenge"
  ) {
    nextAction = "throttle";
  }

  let nextContainmentAction = safeString(baseRisk.containmentAction || "none", 50);
  if (anomalyScore >= 70 && nextContainmentAction === "none") {
    nextContainmentAction = "step_up_verification";
  } else if (anomalyScore >= 40 && nextContainmentAction === "none") {
    nextContainmentAction = "slow_down_actor";
  }

  return {
    ...baseRisk,
    riskScore: nextScore,
    action: nextAction,
    containmentAction: nextContainmentAction,
    reasons: nextReasons.slice(0, 50)
  };
}

function buildInlineSecurityStatus({
  adaptiveModeResult = null,
  containmentResult = null
} = {}) {
  const mode = safeString(adaptiveModeResult?.mode || "normal", 30).toLowerCase();
  const counters =
    adaptiveModeResult && typeof adaptiveModeResult.counters === "object"
      ? adaptiveModeResult.counters
      : {};

  const totalSignals = safeInt(counters.totalSignals, 0, 0, 1_000_000);
  const criticalSignals = safeInt(counters.criticalSignals, 0, 0, 1_000_000);
  const blockSignals = safeInt(counters.blockSignals, 0, 0, 1_000_000);
  const challengeSignals = safeInt(counters.challengeSignals, 0, 0, 1_000_000);
  const repeatedOffenderSignals = safeInt(counters.repeatedOffenderSignals, 0, 0, 1_000_000);
  const lockdownTriggers = safeInt(counters.lockdownTriggers, 0, 0, 1_000_000);
  const highRiskStateSignals = safeInt(counters.highRiskStateSignals, 0, 0, 1_000_000);
  const routePressureSignals = safeInt(counters.routePressureSignals, 0, 0, 1_000_000);

  let threatPressure = 0;
  threatPressure += Math.min(20, totalSignals * 2);
  threatPressure += Math.min(20, criticalSignals * 5);
  threatPressure += Math.min(15, blockSignals * 4);
  threatPressure += Math.min(10, challengeSignals * 2);
  threatPressure += Math.min(15, repeatedOffenderSignals * 4);
  threatPressure += Math.min(10, lockdownTriggers * 5);
  threatPressure += Math.min(5, highRiskStateSignals * 2);
  threatPressure += Math.min(5, routePressureSignals * 2);

  if (mode === "elevated") threatPressure = Math.max(threatPressure, 35);
  if (mode === "defense") threatPressure = Math.max(threatPressure, 65);
  if (mode === "lockdown") threatPressure = Math.max(threatPressure, 90);

  return {
    mode,
    threatPressure: Math.min(100, Math.max(0, threatPressure)),
    containment: {
      mode: safeString(containmentResult?.mode || "normal", 30).toLowerCase(),
      flags: containmentResult?.flags || {}
    }
  };
}

function buildInlineSecurityMetrics({
  securityStatus = null,
  recentEvents = []
} = {}) {
  const events = Array.isArray(recentEvents) ? recentEvents : [];

  const bySeverity = {
    info: 0,
    warning: 0,
    error: 0,
    critical: 0
  };

  const byAction = {
    allow: 0,
    challenge: 0,
    throttle: 0,
    block: 0,
    contain: 0,
    observe: 0
  };

  let recentHighSeverityCount = 0;
  let containmentEventCount = 0;
  let unauthorizedAdminAttempts = 0;

  for (const event of events) {
    const severity = safeString(event?.severity || "", 20).toLowerCase();
    const action = safeString(event?.action || "", 20).toLowerCase();
    const type = safeString(event?.type || "", 120).toLowerCase();

    if (severity in bySeverity) {
      bySeverity[severity] += 1;
    }

    if (action in byAction) {
      byAction[action] += 1;
    }

    if (severity === "warning" || severity === "error" || severity === "critical") {
      recentHighSeverityCount += 1;
    }

    if (type.startsWith("containment_")) {
      containmentEventCount += 1;
    }

    if (type === "admin_endpoint_unauthorized") {
      unauthorizedAdminAttempts += 1;
    }
  }

  return {
    mode: safeString(securityStatus?.mode || "normal", 30).toLowerCase(),
    threatPressure: safeInt(securityStatus?.threatPressure, 0, 0, 100),
    eventCounts: {
      bySeverity,
      byAction
    },
    highlights: {
      recentHighSeverityCount,
      containmentEventCount,
      unauthorizedAdminAttempts
    }
  };
}

function pickFinalAction({
  containment,
  risk,
  rateLimitResult,
  adaptiveModeResult
}) {
  const riskAction = normalizeAction(risk?.action || "allow");
  const containmentAction = normalizeAction(containment?.action || "allow");
  const rateLimitAction = normalizeAction(
    rateLimitResult?.recommendedAction || "allow"
  );
  const adaptiveMode = safeString(
    adaptiveModeResult?.mode || "normal",
    20
  ).toLowerCase();

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

  if (
    adaptiveModeResult?.mode === "elevated" &&
    risk?.containmentAction === "none"
  ) {
    return "slow_down_actor";
  }

  return safeString(risk?.containmentAction || "none", 50);
}

function buildRiskStateIncrements({
  risk = null,
  rateLimitResult = null,
  freshnessResult = null,
  abuseSuccess = true
} = {}) {
  const finalAction = normalizeAction(risk?.finalAction || risk?.action || "allow");
  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);

  return {
    suspiciousEventCount: riskScore >= 45 ? 1 : 0,
    challengeCount: finalAction === "challenge" ? 1 : 0,
    throttleCount: finalAction === "throttle" ? 1 : 0,
    blockCount: finalAction === "block" ? 1 : 0,
    rateLimitHitCount: rateLimitResult && !rateLimitResult.allowed ? 1 : 0,
    captchaFailureCount: freshnessResult && !freshnessResult.ok ? 1 : 0,
    trustedEventCount:
      finalAction === "allow" && riskScore <= 20 && safeBoolean(abuseSuccess) ? 1 : 0
  };
}

async function persistActorRiskStates({
  actor,
  risk,
  rateLimitResult,
  freshnessResult,
  abuseSuccess
}) {
  const updates = [];
  const increments = buildRiskStateIncrements({
    risk,
    rateLimitResult,
    freshnessResult,
    abuseSuccess
  });

  if (actor?.sessionId) {
    updates.push(
      updateRiskState({
        actorType: "session",
        actorId: actor.sessionId,
        riskResult: risk,
        reason: "request_risk_evaluated",
        increments
      })
    );
  }

  if (actor?.userId) {
    updates.push(
      updateRiskState({
        actorType: "user",
        actorId: actor.userId,
        riskResult: risk,
        reason: "request_risk_evaluated",
        increments
      })
    );
  }

  if (actor?.ip && actor.ip !== "unknown") {
    updates.push(
      updateRiskState({
        actorType: "ip",
        actorId: actor.ip,
        riskResult: risk,
        reason: "request_risk_evaluated",
        increments
      })
    );
  }

  if (!updates.length) {
    return [];
  }

  try {
    return await Promise.all(updates);
  } catch (error) {
    console.error("Persistent risk state update failed:", error);
    return [];
  }
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

  const routeSensitivity = inferRouteSensitivity(actor.route, containmentConfig);

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
      success: safeBoolean(abuseSuccess)
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

  let securityState = null;
  try {
    const firestoreState = await getSecurityStateSummary({
      userId: actor.userId,
      email: context?.email || body?.email || "",
      ip: actor.ip,
      sessionId: actor.sessionId
    });

    const persistentRiskStates = await getPersistentRiskStates({
      userId: actor.userId,
      ip: actor.ip,
      sessionId: actor.sessionId
    });

    securityState = mergeSecuritySummaries(firestoreState, persistentRiskStates);
  } catch (error) {
    console.error("Security state read failed:", error);
  }

  let threatResult = null;
  try {
    threatResult = await evaluateThreat({
      ip: actor.ip,
      sessionId: actor.sessionId,
      userId: actor.userId,
      route: actor.route,
      routeSensitivity,
      botResult,
      abuseResult,
      rateLimitResult,
      freshnessResult,
      securityState
    });
  } catch (error) {
    console.error("Threat intelligence failed:", error);
  }

  let baseRisk = {
    riskScore: 0,
    level: "low",
    action: "allow",
    containmentAction: "none",
    hardBlockSignals: 0,
    reasons: []
  };

  try {
    const evaluated = evaluateRisk({
      botResult,
      abuseResult,
      rateLimitResult,
      freshnessResult,
      threatResult,
      securityState,
      routeSensitivity
    });

    if (evaluated && typeof evaluated === "object") {
      baseRisk = evaluated;
    }
  } catch (error) {
    console.error("Risk evaluation failed:", error);
  }

  let anomalyResult = null;
  try {
    const anomalyActorType = actor.userId
      ? "user"
      : actor.sessionId
        ? "session"
        : actor.ip && actor.ip !== "unknown"
          ? "ip"
          : "";

    const anomalyActorId = actor.userId || actor.sessionId || actor.ip || "";

    anomalyResult = anomalyActorType
      ? await evaluateAnomalyDetection({
          actorType: anomalyActorType,
          actorId: anomalyActorId,
          ip: actor.ip,
          route: actor.route,
          riskScore: baseRisk.riskScore,
          isWriteAction: safeBoolean(containmentConfig.isWriteAction),
          actionType: safeString(containmentConfig.actionType || "", 50)
        })
      : null;
  } catch (error) {
    console.error("Anomaly detection failed:", error);
  }

  const risk = mergeAnomalyIntoRisk(baseRisk, anomalyResult);

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
      botResult,
      securityState,
      routeSensitivity
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

  const finalRisk = {
    ...risk,
    routeSensitivity,
    finalAction,
    finalContainmentAction
  };

  const persistentRiskState = await persistActorRiskStates({
    actor,
    risk: finalRisk,
    rateLimitResult,
    freshnessResult,
    abuseSuccess
  });

  let alertsResult = null;
  try {
    const recentEvents = await getRecentSecurityEvents({ limit: 100 });
    const securityStatus = buildInlineSecurityStatus({
      adaptiveModeResult,
      containmentResult
    });
    const securityMetrics = buildInlineSecurityMetrics({
      securityStatus,
      recentEvents
    });

    alertsResult = await evaluateSecurityAlerts({
      securityStatus,
      securityMetrics,
      events: recentEvents,
      anomalyResult,
      risk: finalRisk
    });
  } catch (error) {
    console.error("Security alert evaluation failed:", error);
  }

  return {
    actor,
    risk: finalRisk,
    signals: buildSafeSignalBundle({
      botResult,
      abuseResult,
      rateLimitResult,
      freshnessResult,
      threatResult,
      containmentResult,
      adaptiveModeResult,
      anomalyResult,
      securityState,
      persistentRiskState,
      alertsResult
    })
  };
}
