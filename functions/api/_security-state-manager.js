const MAX_ID_LENGTH = 128;
const MAX_TYPE_LENGTH = 60;
const MAX_ROUTE_GROUP_LENGTH = 80;
const MAX_SOURCE_LENGTH = 50;
const MAX_LEVEL_LENGTH = 20;

const GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token";
const FIRESTORE_BASE_URL = "https://firestore.googleapis.com/v1";
const FIRESTORE_SCOPE = "https://www.googleapis.com/auth/datastore";

const FIRESTORE_RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);

let tokenCache = {
  accessToken: "",
  expiresAt: 0
};

/* -------------------- CORE SAFETY -------------------- */

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
  return Number.isFinite(num) ? Math.min(max, Math.max(min, num)) : fallback;
}

function clampRiskScore(score) {
  return Math.min(100, Math.max(0, safeInt(score, 0, 0, 100)));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* -------------------- NORMALIZATION -------------------- */

function normalizeId(value = "", maxLength = MAX_ID_LENGTH) {
  return safeString(value || "", maxLength).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function normalizeHash(value = "", maxLength = 64) {
  return safeString(value || "", maxLength)
    .toLowerCase()
    .replace(/[^a-f0-9]/g, "")
    .slice(0, maxLength);
}

function normalizeLevel(value = "") {
  const level = safeString(value || "warning", MAX_LEVEL_LENGTH).toLowerCase();
  return ["info", "warning", "error", "critical"].includes(level)
    ? level
    : "warning";
}

function normalizeType(value = "") {
  return safeString(value || "unknown", MAX_TYPE_LENGTH).toLowerCase();
}

function normalizeRouteGroup(value = "") {
  return safeString(value || "unknown", MAX_ROUTE_GROUP_LENGTH).toLowerCase();
}

function normalizeSource(value = "") {
  return safeString(value || "unspecified", MAX_SOURCE_LENGTH).toLowerCase();
}

function normalizeEvent(event = {}) {
  return {
    type: normalizeType(event.type),
    level: normalizeLevel(event.level),
    routeGroup: normalizeRouteGroup(event.routeGroup || "unknown"),
    source: normalizeSource(event.source),
    kind: safeString(event.kind || "unknown", 30),
    refId: safeString(event.refId || "", MAX_ID_LENGTH),
    userId: normalizeId(event.userId || ""),
    emailHash: normalizeHash(event.emailHash || ""),
    ipHash: normalizeHash(event.ipHash || ""),
    sessionId: normalizeId(event.sessionId || ""),
    degraded: event.degraded === true
  };
}

function hasFirebaseAdminEnv(env) {
  return Boolean(
    safeString(env?.FIREBASE_PROJECT_ID || "", 200) &&
      safeString(env?.FIREBASE_CLIENT_EMAIL || "", 500) &&
      safeString(env?.FIREBASE_PRIVATE_KEY || "", 20000)
  );
}

/* -------------------- RISK / SEVERITY -------------------- */

function getSeverityWeight(level = "") {
  const normalized = normalizeLevel(level);

  if (normalized === "critical") return 10;
  if (normalized === "error") return 6;
  if (normalized === "warning") return 3;
  return 1;
}

function getRiskDeltaByType(type = "", level = "") {
  const normalizedType = normalizeType(type);
  const severityWeight = getSeverityWeight(level);

  if (
    normalizedType.includes("login_failed") ||
    normalizedType.includes("signup_failed") ||
    normalizedType.includes("turnstile_verification_failed") ||
    normalizedType.includes("password_reset_failed")
  ) {
    return 3 * severityWeight;
  }

  if (
    normalizedType.includes("lockout") ||
    normalizedType.includes("blocked") ||
    normalizedType.includes("forbidden") ||
    normalizedType.includes("rate_limited")
  ) {
    return 5 * severityWeight;
  }

  if (
    normalizedType.includes("suspicious") ||
    normalizedType.includes("challenge") ||
    normalizedType.includes("throttle") ||
    normalizedType.includes("exploit") ||
    normalizedType.includes("breach") ||
    normalizedType.includes("replay") ||
    normalizedType.includes("coordinated")
  ) {
    return 4 * severityWeight;
  }

  if (
    normalizedType.includes("success") ||
    normalizedType.includes("verified")
  ) {
    return -2;
  }

  return severityWeight;
}

function getRiskLevel(score = 0) {
  const normalized = clampRiskScore(score);

  if (normalized >= 80) return "critical";
  if (normalized >= 55) return "high";
  if (normalized >= 25) return "medium";
  return "low";
}

function shouldIncrementCounter(type = "", matchers = []) {
  const normalizedType = normalizeType(type);
  return matchers.some((matcher) => normalizedType.includes(matcher));
}

/* -------------------- DOC IDS -------------------- */

function buildEntityDocId(kind, id) {
  return normalizeId(`${kind}_${id}`, MAX_ID_LENGTH);
}

/* -------------------- AUTH / OAUTH -------------------- */

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

function clearAccessTokenCache() {
  tokenCache = {
    accessToken: "",
    expiresAt: 0
  };
}

/* -------------------- FIRESTORE CONVERSION -------------------- */

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

function toFirestoreValue(value) {
  if (value === null || value === undefined) {
    return { nullValue: null };
  }

  if (typeof value === "string") {
    return { stringValue: value };
  }

  if (typeof value === "boolean") {
    return { booleanValue: value };
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) return { nullValue: null };
    if (Number.isInteger(value)) return { integerValue: String(value) };
    return { doubleValue: value };
  }

  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map((item) => toFirestoreValue(item))
      }
    };
  }

  if (typeof value === "object") {
    const fields = {};
    for (const [key, val] of Object.entries(value)) {
      const safeKey = safeString(key, 100);
      if (safeKey) {
        fields[safeKey] = toFirestoreValue(val);
      }
    }
    return { mapValue: { fields } };
  }

  return { stringValue: safeString(value, 500) };
}

function toFirestoreDocumentFields(data) {
  const fields = {};
  for (const [key, value] of Object.entries(data)) {
    const safeKey = safeString(key, 100);
    if (safeKey) {
      fields[safeKey] = toFirestoreValue(value);
    }
  }
  return fields;
}

async function firestoreFetchWithRetry(fetcher, retryCount = 2) {
  let lastError = null;

  for (let attempt = 0; attempt <= retryCount; attempt += 1) {
    try {
      return await fetcher();
    } catch (error) {
      lastError = error;

      const status = safeInt(error?.status, 0);
      if (attempt >= retryCount || !FIRESTORE_RETRYABLE_STATUS.has(status)) {
        break;
      }

      await sleep(150 * (attempt + 1));
    }
  }

  throw lastError || new Error("Firestore request failed.");
}

async function firestoreGetDocument(env, collectionName, documentId, retry = true) {
  return firestoreFetchWithRetry(async () => {
    const projectId = safeString(env?.FIREBASE_PROJECT_ID || "", 200);
    const accessToken = await getAccessToken(env);

    const url =
      `${FIRESTORE_BASE_URL}/projects/${encodeURIComponent(projectId)}` +
      `/databases/(default)/documents/${encodeURIComponent(collectionName)}/${encodeURIComponent(documentId)}`;

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
      const error = new Error(
        `Firestore read failed: ${response.status} ${safeString(errorText, 500)}`
      );
      error.status = response.status;

      if ((response.status === 401 || response.status === 403) && retry) {
        clearAccessTokenCache();
        return firestoreGetDocument(env, collectionName, documentId, false);
      }

      throw error;
    }

    const data = await response.json();
    return fromFirestoreDocument(data);
  });
}

async function firestorePatchDocument(env, collectionName, documentId, payload, retry = true) {
  return firestoreFetchWithRetry(async () => {
    const projectId = safeString(env?.FIREBASE_PROJECT_ID || "", 200);
    const accessToken = await getAccessToken(env);

    const url =
      `${FIRESTORE_BASE_URL}/projects/${encodeURIComponent(projectId)}` +
      `/databases/(default)/documents/${encodeURIComponent(collectionName)}/${encodeURIComponent(documentId)}`;

    const response = await fetch(url, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        fields: toFirestoreDocumentFields(payload)
      })
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      const error = new Error(
        `Firestore patch failed: ${response.status} ${safeString(errorText, 500)}`
      );
      error.status = response.status;

      if ((response.status === 401 || response.status === 403) && retry) {
        clearAccessTokenCache();
        return firestorePatchDocument(env, collectionName, documentId, payload, false);
      }

      throw error;
    }

    return true;
  });
}

/* -------------------- PATCH BUILDERS -------------------- */

function buildBasePatch(existing = {}, event = {}) {
  const nowMs = Date.now();
  const level = normalizeLevel(event.level);
  const type = normalizeType(event.type);
  const routeGroup = normalizeRouteGroup(event.routeGroup || "unknown");
  const source = normalizeSource(event.source);
  const severityWeight = getSeverityWeight(level);
  const riskDelta = getRiskDeltaByType(type, level);

  return {
    kind: safeString(event.kind || "unknown", 30),
    refId: safeString(event.refId || "", MAX_ID_LENGTH),
    lastEventType: type,
    lastLevel: level,
    lastSource: source,
    lastRouteGroup: routeGroup,
    lastSeenAtMs: nowMs,
    lastSeenAtIso: new Date(nowMs).toISOString(),
    totalEvents: safeInt(existing.totalEvents, 0) + 1,
    totalSeverityWeight: safeInt(existing.totalSeverityWeight, 0) + severityWeight,
    rollingRiskScoreDelta: Math.max(
      0,
      safeInt(existing.rollingRiskScoreDelta, 0) + riskDelta
    )
  };
}

function buildCounterPatch(existing = {}, event = {}) {
  const type = normalizeType(event.type);
  const level = normalizeLevel(event.level);

  const patch = {
    criticalEvents: safeInt(existing.criticalEvents, 0),
    errorEvents: safeInt(existing.errorEvents, 0),
    warningEvents: safeInt(existing.warningEvents, 0),
    infoEvents: safeInt(existing.infoEvents, 0),

    failedLoginCount: safeInt(existing.failedLoginCount, 0),
    failedSignupCount: safeInt(existing.failedSignupCount, 0),
    failedPasswordResetCount: safeInt(existing.failedPasswordResetCount, 0),
    passwordResetRequestCount: safeInt(existing.passwordResetRequestCount, 0),
    captchaFailureCount: safeInt(existing.captchaFailureCount, 0),
    suspiciousEventCount: safeInt(existing.suspiciousEventCount, 0),
    rateLimitHitCount: safeInt(existing.rateLimitHitCount, 0),
    lockoutCount: safeInt(existing.lockoutCount, 0),
    successfulAuthCount: safeInt(existing.successfulAuthCount, 0),

    exploitFlagCount: safeInt(existing.exploitFlagCount, 0),
    breachFlagCount: safeInt(existing.breachFlagCount, 0),
    replayFlagCount: safeInt(existing.replayFlagCount, 0),
    coordinatedFlagCount: safeInt(existing.coordinatedFlagCount, 0)
  };

  if (level === "critical") patch.criticalEvents += 1;
  else if (level === "error") patch.errorEvents += 1;
  else if (level === "warning") patch.warningEvents += 1;
  else patch.infoEvents += 1;

  if (shouldIncrementCounter(type, ["login_failed"])) patch.failedLoginCount += 1;
  if (shouldIncrementCounter(type, ["signup_failed"])) patch.failedSignupCount += 1;
  if (shouldIncrementCounter(type, ["password_reset_failed"])) patch.failedPasswordResetCount += 1;
  if (shouldIncrementCounter(type, ["password_reset_requested"])) patch.passwordResetRequestCount += 1;

  if (
    shouldIncrementCounter(type, [
      "turnstile_verification_failed",
      "captcha_missing",
      "captcha_failed",
      "replay"
    ])
  ) {
    patch.captchaFailureCount += 1;
  }

  if (
    shouldIncrementCounter(type, [
      "blocked",
      "forbidden",
      "challenge",
      "throttle",
      "suspicious",
      "exploit",
      "breach",
      "replay",
      "coordinated"
    ])
  ) {
    patch.suspiciousEventCount += 1;
  }

  if (shouldIncrementCounter(type, ["rate_limited"])) patch.rateLimitHitCount += 1;
  if (shouldIncrementCounter(type, ["lockout", "ip_login_lock"])) patch.lockoutCount += 1;

  if (
    shouldIncrementCounter(type, [
      "login_success",
      "signup_success",
      "google_login_success"
    ])
  ) {
    patch.successfulAuthCount += 1;
  }

  if (shouldIncrementCounter(type, ["exploit"])) patch.exploitFlagCount += 1;
  if (shouldIncrementCounter(type, ["breach"])) patch.breachFlagCount += 1;
  if (shouldIncrementCounter(type, ["replay"])) patch.replayFlagCount += 1;
  if (shouldIncrementCounter(type, ["coordinated"])) patch.coordinatedFlagCount += 1;

  return patch;
}

function buildRiskPatch(existing = {}, event = {}) {
  const currentRolling = safeInt(existing.rollingRiskScoreDelta, 0, 0, 100000);
  const delta = getRiskDeltaByType(event.type, event.level);
  const nextRolling = Math.max(0, currentRolling + delta);

  const normalizedRiskScore = clampRiskScore(
    Math.min(100, Math.floor(nextRolling / 3))
  );

  return {
    currentRiskScore: normalizedRiskScore,
    currentRiskLevel: getRiskLevel(normalizedRiskScore),
    lastRiskDelta: delta
  };
}

function buildStatePatch(existing = {}, event = {}) {
  const patch = {
    ...buildBasePatch(existing, event),
    ...buildCounterPatch(existing, event),
    ...buildRiskPatch(existing, event)
  };

  if (event.degraded === true) {
    patch.lastDegradedAtMs = Date.now();
    patch.degradedEventCount = safeInt(existing.degradedEventCount, 0) + 1;
  }

  return patch;
}

/* -------------------- ENTITY UPDATE -------------------- */

async function updateEntityState(env, kind, refId, event) {
  if (!refId) {
    return false;
  }

  const documentId = buildEntityDocId(kind, refId);
  const existing =
    (await firestoreGetDocument(env, "securityState", documentId)) || {};

  const patch = buildStatePatch(existing, {
    ...event,
    kind,
    refId
  });

  try {
    await firestorePatchDocument(env, "securityState", documentId, patch);
    return true;
  } catch (error) {
    console.error(`Failed to update security state for ${kind}:`, error);
    return false;
  }
}

function getEntityTargets(event = {}) {
  const targets = [];

  const userId = normalizeId(event.userId || "");
  const emailHash = normalizeHash(event.emailHash || "");
  const ipHash = normalizeHash(event.ipHash || "");
  const sessionId = normalizeId(event.sessionId || "");

  if (userId) targets.push({ kind: "user", refId: userId });
  if (emailHash) targets.push({ kind: "email", refId: emailHash });
  if (ipHash) targets.push({ kind: "ip", refId: ipHash });
  if (sessionId) targets.push({ kind: "session", refId: sessionId });

  return targets;
}

/* -------------------- PUBLIC API -------------------- */

export async function updateSecurityState(input = {}) {
  const env = input?.env || null;
  const rawEvent = input?.event || null;

  if (!env || !hasFirebaseAdminEnv(env) || !rawEvent || typeof rawEvent !== "object") {
    return { ok: false, updated: 0, degraded: true };
  }

  const event = normalizeEvent(rawEvent);
  const targets = getEntityTargets(rawEvent);

  if (!targets.length) {
    return { ok: true, updated: 0, degraded: false };
  }

  const results = await Promise.all(
    targets.map((target) =>
      updateEntityState(env, target.kind, target.refId, event)
    )
  );

  const updated = results.filter(Boolean).length;

  return {
    ok: updated > 0,
    updated,
    degraded: updated !== targets.length
  };
}
