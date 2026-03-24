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
import { buildSecurityMetrics } from "./_security-metrics.js";

const GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token";
const FIRESTORE_BASE_URL = "https://firestore.googleapis.com/v1";
const FIRESTORE_SCOPE = "https://www.googleapis.com/auth/datastore";

let tokenCache = {
  accessToken: "",
  expiresAt: 0
};

/* -------------------- SAFETY -------------------- */

function safeString(value, maxLength = 200) {
  return String(value ?? "")
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

/* -------------------- FIRESTORE AUTH -------------------- */

function hasFirestoreEnv(env = {}) {
  return Boolean(
    safeString(env?.FIREBASE_PROJECT_ID || "", 200) &&
      safeString(env?.FIREBASE_CLIENT_EMAIL || "", 500) &&
      safeString(env?.FIREBASE_PRIVATE_KEY || "", 20000)
  );
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlEncodeString(input = "") {
  return base64UrlEncodeBytes(new TextEncoder().encode(input));
}

function pemToArrayBuffer(pem = "") {
  const cleaned = String(pem || "")
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");

  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

async function importPrivateKey(privateKeyPem) {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKeyPem),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );
}

async function createServiceJwt(env) {
  const clientEmail = safeString(env?.FIREBASE_CLIENT_EMAIL || "", 500);
  const privateKey = safeString(env?.FIREBASE_PRIVATE_KEY || "", 20000).replace(/\\n/g, "\n");

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claimSet = {
    iss: clientEmail,
    scope: FIRESTORE_SCOPE,
    aud: GOOGLE_OAUTH_TOKEN_URL,
    exp: now + 3600,
    iat: now
  };

  const encodedHeader = base64UrlEncodeString(JSON.stringify(header));
  const encodedClaimSet = base64UrlEncodeString(JSON.stringify(claimSet));
  const unsignedToken = `${encodedHeader}.${encodedClaimSet}`;

  const cryptoKey = await importPrivateKey(privateKey);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(unsignedToken)
  );

  const encodedSignature = base64UrlEncodeBytes(new Uint8Array(signature));
  return `${unsignedToken}.${encodedSignature}`;
}

async function getAccessToken(env) {
  const now = Date.now();

  if (tokenCache.accessToken && tokenCache.expiresAt > now + 60 * 1000) {
    return tokenCache.accessToken;
  }

  const assertion = await createServiceJwt(env);

  const response = await fetch(GOOGLE_OAUTH_TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "");
    throw new Error(
      `OAuth token request failed: ${response.status} ${safeString(errorText, 300)}`
    );
  }

  const data = await response.json();
  const accessToken = safeString(data?.access_token || "", 5000);
  const expiresInMs = safeInt(data?.expires_in, 3600, 60, 3600) * 1000;

  if (!accessToken) {
    throw new Error("OAuth token missing access_token.");
  }

  tokenCache = {
    accessToken,
    expiresAt: now + expiresInMs
  };

  return accessToken;
}

/* -------------------- HASHING -------------------- */

async function sha256Hex(input = "") {
  const bytes = new TextEncoder().encode(String(input || ""));
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function deriveIpHash(ip = "") {
  const normalizedIp = safeString(ip || "", 100);
  if (!normalizedIp || normalizedIp === "unknown") {
    return "";
  }

  return (await sha256Hex(normalizedIp)).slice(0, 32);
}

async function deriveEmailHash(email = "") {
  const normalizedEmail = safeString(email || "", 200).toLowerCase();
  if (!normalizedEmail) {
    return "";
  }

  return (await sha256Hex(normalizedEmail)).slice(0, 64);
}

/* -------------------- HELPERS -------------------- */

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

/* -------------------- FIRESTORE STATE READING -------------------- */

function fromFirestoreValue(value) {
  if (!value || typeof value !== "object") return null;

  if ("stringValue" in value) return value.stringValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("booleanValue" in value) return Boolean(value.booleanValue);
  if ("nullValue" in value) return null;

  if ("arrayValue" in value) {
    const values = value.arrayValue?.values || [];
    return values.map(fromFirestoreValue);
  }

  if ("mapValue" in value) {
    const fields = value.mapValue?.fields || {};
    const output = {};
    for (const [key, val] of Object.entries(fields)) {
      output[key] = fromFirestoreValue(val);
    }
    return output;
  }

  return null;
}

function fromFirestoreDocument(doc) {
  const fields = doc?.fields || {};
  const output = {};

  for (const [key, value] of Object.entries(fields)) {
    output[key] = fromFirestoreValue(value);
  }

  return output;
}

async function readSecurityStateDoc(env, docId) {
  if (!docId || !hasFirestoreEnv(env)) {
    return null;
  }

  try {
    const projectId = safeString(env?.FIREBASE_PROJECT_ID || "", 200);
    const accessToken = await getAccessToken(env);

    const url =
      `${FIRESTORE_BASE_URL}/projects/${encodeURIComponent(projectId)}` +
      `/databases/(default)/documents/securityState/${encodeURIComponent(docId)}`;

    const response = await fetch(url, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      throw new Error(
        `Security state read failed: ${response.status} ${safeString(errorText, 300)}`
      );
    }

    const data = await response.json();
    return fromFirestoreDocument(data);
  } catch (error) {
    console.error("Security state read failed:", error);
    return null;
  }
}

async function getSecurityStateSummary({
  env = {},
  userId = "",
  email = "",
  ip = "",
  sessionId = ""
} = {}) {
  const safeUserId = safeString(userId || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  const safeSessionId = safeString(sessionId || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  const emailHash = await deriveEmailHash(email || "");
  const ipHash = await deriveIpHash(ip || "");

  const targets = [
    safeUserId ? `user_${safeUserId}` : "",
    emailHash ? `email_${emailHash}` : "",
    ipHash ? `ip_${ipHash}` : "",
    safeSessionId ? `session_${safeSessionId}` : ""
  ].filter(Boolean);

  if (!targets.length) {
    return null;
  }

  const docs = await Promise.all(
    targets.map((docId) => readSecurityStateDoc(env, docId))
  );

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
    successfulAuthCount: 0,
    exploitFlagCount: 0,
    breachFlagCount: 0,
    replayFlagCount: 0,
    coordinatedFlagCount: 0
  };

  for (const doc of docs) {
    if (!doc || typeof doc !== "object") continue;

    merged.currentRiskScore = Math.max(
      merged.currentRiskScore,
      safeInt(doc.currentRiskScore, 0, 0, 100)
    );

    const docRiskLevel = safeString(doc.currentRiskLevel || "", 20).toLowerCase();

    if (docRiskLevel === "critical") {
      merged.currentRiskLevel = "critical";
    } else if (merged.currentRiskLevel !== "critical" && docRiskLevel === "high") {
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
    merged.exploitFlagCount += safeInt(doc.exploitFlagCount, 0, 0, 100000);
    merged.breachFlagCount += safeInt(doc.breachFlagCount, 0, 0, 100000);
    merged.replayFlagCount += safeInt(doc.replayFlagCount, 0, 0, 100000);
    merged.coordinatedFlagCount += safeInt(doc.coordinatedFlagCount, 0, 0, 100000);
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
    successfulAuthCount: 0,
    exploitFlagCount: 0,
    breachFlagCount: 0,
    replayFlagCount: 0,
    coordinatedFlagCount: 0
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
    merged.exploitFlagCount += safeInt(baseState.exploitFlagCount, 0, 0, 100000);
    merged.breachFlagCount += safeInt(baseState.breachFlagCount, 0, 0, 100000);
    merged.replayFlagCount += safeInt(baseState.replayFlagCount, 0, 0, 100000);
    merged.coordinatedFlagCount += safeInt(baseState.coordinatedFlagCount, 0, 0, 100000);
  }

  for (const state of Array.isArray(persistentStates) ? persistentStates : []) {
    if (!state || typeof state !== "object") continue;

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
    merged.exploitFlagCount += safeInt(state.exploitFlagCount, 0, 0, 100000);
    merged.breachFlagCount += safeInt(state.breachFlagCount, 0, 0, 100000);
    merged.replayFlagCount += safeInt(state.replayFlagCount, 0, 0, 100000);
    merged.coordinatedFlagCount += safeInt(state.coordinatedFlagCount, 0, 0, 100000);
  }

  return merged;
}

async function getPersistentRiskStates({
  env = {},
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
        env,
        actorType: "session",
        actorId: safeSessionId
      })
    );
  }

  if (safeUserId) {
    requests.push(
      getRiskState({
        env,
        actorType: "user",
        actorId: safeUserId
      })
    );
  }

  if (safeIp && safeIp !== "unknown") {
    requests.push(
      getRiskState({
        env,
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

function buildEnforcementFlags({
  containmentResult = null,
  adaptiveModeResult = null,
  risk = null,
  anomalyResult = null
} = {}) {
  const flags = containmentResult?.flags || {};
  const adaptiveMode = safeString(adaptiveModeResult?.mode || "normal", 30).toLowerCase();
  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);
  const hardBlockSignals =
    safeInt(risk?.hardBlockSignals, 0, 0, 100) +
    safeInt(anomalyResult?.events?.hardBlockSignals, 0, 0, 100);
  const exploitSignals =
    safeInt(risk?.events?.exploitSignals, 0, 0, 100) +
    safeInt(anomalyResult?.events?.exploitSignals, 0, 0, 100);
  const breachSignals =
    safeInt(risk?.events?.breachSignals, 0, 0, 100) +
    safeInt(anomalyResult?.events?.breachSignals, 0, 0, 100);

  const criticalAttack =
    adaptiveMode === "lockdown" ||
    safeBoolean(risk?.criticalAttackLikely) ||
    breachSignals > 0 ||
    exploitSignals > 0 ||
    hardBlockSignals >= 2;

  return {
    shouldBlockActor: flags.blockActor === true,
    shouldLockAccount: flags.lockAccount === true,
    shouldKillSessions: flags.killSessions === true,
    forceCaptcha: flags.forceCaptcha === true,
    isGlobalLockdown: flags.lockdown === true || adaptiveMode === "lockdown",
    criticalAttack,
    highRisk: riskScore >= 70
  };
}

function pickFinalAction({
  containment,
  risk,
  rateLimitResult,
  adaptiveModeResult,
  anomalyResult,
  enforcementFlags
}) {
  const riskAction = normalizeAction(risk?.action || "allow");
  const containmentAction = normalizeAction(containment?.action || "allow");
  const rateLimitAction = normalizeAction(
    rateLimitResult?.recommendedAction || "allow"
  );
  const anomalyAction = normalizeAction(anomalyResult?.action || "allow");
  const adaptiveMode = safeString(
    adaptiveModeResult?.mode || "normal",
    20
  ).toLowerCase();

  if (enforcementFlags?.shouldBlockActor) return "block";
  if (enforcementFlags?.shouldLockAccount) return "block";
  if (containment?.blocked) return "block";
  if (enforcementFlags?.isGlobalLockdown) return "block";
  if (enforcementFlags?.criticalAttack) return "block";

  if (riskAction === "block" || anomalyAction === "block") {
    return "block";
  }

  if (rateLimitResult && !rateLimitResult.allowed) {
    if (rateLimitAction === "block") return "block";
    if (rateLimitAction === "challenge") return "challenge";
    if (rateLimitAction === "throttle") return "throttle";
  }

  if (containmentAction === "challenge") return "challenge";
  if (enforcementFlags?.forceCaptcha) return "challenge";

  if (adaptiveMode === "defense" && riskAction === "allow") {
    return "challenge";
  }

  if (adaptiveMode === "elevated" && riskAction === "allow") {
    return "throttle";
  }

  if (anomalyAction === "challenge" || riskAction === "challenge") {
    return "challenge";
  }

  if (anomalyAction === "throttle" || riskAction === "throttle") {
    return "throttle";
  }

  return "allow";
}

function pickFinalContainmentAction({
  containment,
  risk,
  adaptiveModeResult,
  enforcementFlags
}) {
  if (enforcementFlags?.shouldKillSessions) return "kill_sessions";
  if (enforcementFlags?.shouldLockAccount) return "lock_account";
  if (enforcementFlags?.shouldBlockActor) return "block_actor";
  if (containment?.blocked) return "temporary_containment";
  if (containment?.action === "challenge") return "step_up_verification";
  if (adaptiveModeResult?.mode === "lockdown") return "temporary_containment";
  if (adaptiveModeResult?.mode === "defense") return "step_up_verification";

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
  abuseSuccess = true,
  threatResult = null,
  anomalyResult = null
} = {}) {
  const finalAction = normalizeAction(risk?.finalAction || risk?.action || "allow");
  const riskScore = safeInt(risk?.riskScore, 0, 0, 100);

  const exploitSignals =
    safeInt(threatResult?.events?.exploitSignals, 0, 0, 100) +
    safeInt(anomalyResult?.events?.exploitSignals, 0, 0, 100);

  const breachSignals =
    safeInt(threatResult?.events?.breachSignals, 0, 0, 100) +
    safeInt(anomalyResult?.events?.breachSignals, 0, 0, 100);

  const replaySignals =
    safeInt(threatResult?.signals?.replayPressure, 0, 0, 100) > 0 ||
    safeInt(freshnessResult?.events?.replaySignals, 0, 0, 100) > 0
      ? 1
      : 0;

  const coordinatedSignals =
    safeInt(anomalyResult?.events?.coordinatedSignals, 0, 0, 100) > 0 ? 1 : 0;

  return {
    suspiciousEventCount: riskScore >= 45 ? 1 : 0,
    challengeCount: finalAction === "challenge" ? 1 : 0,
    throttleCount: finalAction === "throttle" ? 1 : 0,
    blockCount: finalAction === "block" ? 1 : 0,
    rateLimitHitCount: rateLimitResult && !rateLimitResult.allowed ? 1 : 0,
    captchaFailureCount: freshnessResult && !freshnessResult.ok ? 1 : 0,
    trustedEventCount:
      finalAction === "allow" && riskScore <= 20 && safeBoolean(abuseSuccess) ? 1 : 0,
    exploitFlagCount: exploitSignals > 0 ? 1 : 0,
    breachFlagCount: breachSignals > 0 ? 1 : 0,
    replayFlagCount: replaySignals,
    coordinatedFlagCount: coordinatedSignals
  };
}

async function persistActorRiskStates({
  env = {},
  actor,
  risk,
  rateLimitResult,
  freshnessResult,
  abuseSuccess,
  threatResult,
  anomalyResult
}) {
  const updates = [];
  const increments = buildRiskStateIncrements({
    risk,
    rateLimitResult,
    freshnessResult,
    abuseSuccess,
    threatResult,
    anomalyResult
  });

  if (actor?.sessionId) {
    updates.push(
      updateRiskState({
        env,
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
        env,
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
        env,
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

/* -------------------- MAIN -------------------- */

export async function runSecurityOrchestrator({
  env = {},
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
      env,
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
      env,
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
        env,
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
        env,
        requestAt: getRequestTimestamp(body),
        nonce: safeString(body.nonce || "", 200),
        scope: safeString(freshnessConfig.scope || actor.route, 100),
        requireNonce: safeBoolean(freshnessConfig.requireNonce),
        requireNonceStorage: safeBoolean(
          freshnessConfig.requireNonceStorage !== false
        ),
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
      env,
      userId: actor.userId,
      email: context?.email || body?.email || "",
      ip: actor.ip,
      sessionId: actor.sessionId
    });

    const persistentRiskStates = await getPersistentRiskStates({
      env,
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
      env,
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

  let risk = {
    riskScore: 0,
    level: "low",
    action: "allow",
    containmentAction: "none",
    hardBlockSignals: 0,
    criticalSignals: 0,
    criticalAttackLikely: false,
    reasons: [],
    events: {
      exploitSignals: 0,
      breachSignals: 0,
      replaySignals: 0,
      coordinatedSignals: 0
    }
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
      risk = {
        ...risk,
        ...evaluated,
        events: {
          ...risk.events,
          ...(evaluated.events && typeof evaluated.events === "object"
            ? evaluated.events
            : {})
        }
      };
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
          env,
          actorType: anomalyActorType,
          actorId: anomalyActorId,
          ip: actor.ip,
          route: actor.route,
          routeSensitivity,
          riskScore: risk.riskScore,
          isWriteAction: safeBoolean(containmentConfig.isWriteAction),
          actionType: safeString(containmentConfig.actionType || "", 50),
          abuseResult,
          rateLimitResult,
          freshnessResult,
          risk
        })
      : null;
  } catch (error) {
    console.error("Anomaly detection failed:", error);
  }

  if (anomalyResult && typeof anomalyResult === "object") {
    const anomalyScore = safeInt(anomalyResult.anomalyScore, 0, 0, 100);
    const anomalyAction = normalizeAction(anomalyResult.action || "allow");
    const anomalyReasons = Array.isArray(anomalyResult.reasons)
      ? anomalyResult.reasons.map((reason) => safeString(reason, 120)).filter(Boolean)
      : [];

    risk = {
      ...risk,
      riskScore: Math.min(
        100,
        safeInt(risk.riskScore, 0, 0, 100) + Math.min(25, Math.floor(anomalyScore / 2))
      ),
      action:
        anomalyAction === "block"
          ? "block"
          : anomalyAction === "challenge" && risk.action !== "block"
            ? "challenge"
            : anomalyAction === "throttle" &&
              !["block", "challenge"].includes(risk.action)
              ? "throttle"
              : risk.action,
      criticalAttackLikely:
        safeBoolean(risk.criticalAttackLikely) ||
        safeInt(anomalyResult?.events?.breachSignals, 0, 0, 100) > 0 ||
        safeInt(anomalyResult?.events?.exploitSignals, 0, 0, 100) > 0,
      reasons: [...new Set([...(risk.reasons || []), ...anomalyReasons])].slice(0, 50),
      events: {
        ...risk.events,
        exploitSignals: Math.max(
          safeInt(risk?.events?.exploitSignals, 0, 0, 100),
          safeInt(anomalyResult?.events?.exploitSignals, 0, 0, 100)
        ),
        breachSignals: Math.max(
          safeInt(risk?.events?.breachSignals, 0, 0, 100),
          safeInt(anomalyResult?.events?.breachSignals, 0, 0, 100)
        ),
        replaySignals: Math.max(
          safeInt(risk?.events?.replaySignals, 0, 0, 100),
          safeInt(anomalyResult?.events?.replaySignals, 0, 0, 100)
        ),
        coordinatedSignals: Math.max(
          safeInt(risk?.events?.coordinatedSignals, 0, 0, 100),
          safeInt(anomalyResult?.events?.coordinatedSignals, 0, 0, 100)
        )
      }
    };
  }

  let containmentResult = null;
  try {
    containmentResult = await evaluateContainment(env, {
      route: actor.route,
      isAdminRoute: safeBoolean(containmentConfig.isAdminRoute),
      isWriteAction: safeBoolean(containmentConfig.isWriteAction),
      actionType: safeString(containmentConfig.actionType || "", 50),
      actorType: actor.userId ? "user" : actor.sessionId ? "session" : "ip",
      actorId: actor.userId || actor.sessionId || actor.ip
    });
  } catch (error) {
    console.error("Containment evaluation failed:", error);
  }

  let adaptiveModeResult = null;
  try {
    adaptiveModeResult = await evaluateAdaptiveThreatMode({
      env,
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

  const enforcement = buildEnforcementFlags({
    containmentResult,
    adaptiveModeResult,
    risk,
    anomalyResult
  });

  const finalAction = pickFinalAction({
    containment: containmentResult,
    risk,
    rateLimitResult,
    adaptiveModeResult,
    anomalyResult,
    enforcementFlags: enforcement
  });

  const finalContainmentAction = pickFinalContainmentAction({
    containment: containmentResult,
    risk,
    adaptiveModeResult,
    enforcementFlags: enforcement
  });

  const finalRisk = {
    ...risk,
    routeSensitivity,
    finalAction,
    finalContainmentAction,
    criticalAttackLikely:
      safeBoolean(risk.criticalAttackLikely) || safeBoolean(enforcement.criticalAttack)
  };

  const persistentRiskState = await persistActorRiskStates({
    env,
    actor,
    risk: finalRisk,
    rateLimitResult,
    freshnessResult,
    abuseSuccess,
    threatResult,
    anomalyResult
  });

  let alertsResult = null;
  try {
    const recentEvents = await getRecentSecurityEvents(env, {
      limit: 100
    });

    const securityStatus = buildInlineSecurityStatus({
      adaptiveModeResult,
      containmentResult
    });

    const securityMetrics = buildSecurityMetrics({
      adaptiveState: adaptiveModeResult || {},
      containmentState: {
        mode: containmentResult?.mode || "normal",
        flags: containmentResult?.flags || {}
      },
      events: recentEvents
    });

    alertsResult = await evaluateSecurityAlerts({
      env,
      securityStatus,
      securityMetrics,
      events: recentEvents,
      anomalyResult,
      risk: finalRisk,
      adaptiveMode: adaptiveModeResult,
      containment: containmentResult
    });
  } catch (error) {
    console.error("Security alert evaluation failed:", error);
  }

  return {
    actor,
    risk: finalRisk,
    enforcement,
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
