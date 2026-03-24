import { updateSecurityState } from "./_security-state-manager.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error",
  "critical"
]);

const ALLOWED_EVENT_ACTIONS = new Set([
  "allow",
  "observe",
  "throttle",
  "challenge",
  "block",
  "contain"
]);

const MAX_TYPE_LENGTH = 60;
const MAX_MESSAGE_LENGTH = 500;
const MAX_EMAIL_LENGTH = 200;
const MAX_EMAIL_HASH_LENGTH = 64;
const MAX_USER_ID_LENGTH = 128;
const MAX_IP_LENGTH = 100;
const MAX_ROUTE_LENGTH = 150;
const MAX_ROUTE_GROUP_LENGTH = 80;
const MAX_SOURCE_LENGTH = 50;
const MAX_EVENT_ID_LENGTH = 80;
const MAX_FINGERPRINT_LENGTH = 64;
const MAX_METADATA_STRING_LENGTH = 1000;
const MAX_METADATA_KEY_LENGTH = 100;
const MAX_METADATA_ITEMS = 30;
const MAX_METADATA_ARRAY_ITEMS = 25;
const MAX_METADATA_DEPTH = 4;

const GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token";
const FIRESTORE_BASE_URL = "https://firestore.googleapis.com/v1";
const FIRESTORE_SCOPE = "https://www.googleapis.com/auth/datastore";

let tokenCache = {
  accessToken: "",
  expiresAt: 0
};

/* -------------------- SAFETY -------------------- */

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

function safeLevel(level) {
  const normalized = safeString(level || "warning", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "warning";
}

function safeEventAction(action = "", fallback = "observe") {
  const normalized = safeString(action || fallback, 20).toLowerCase();
  return ALLOWED_EVENT_ACTIONS.has(normalized) ? normalized : fallback;
}

function isPlainObject(value) {
  if (Object.prototype.toString.call(value) !== "[object Object]") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/* -------------------- NORMALIZATION -------------------- */

function normalizeEmail(value = "") {
  const email = safeString(value || "", MAX_EMAIL_LENGTH).toLowerCase();
  if (!email) return "";
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : "";
}

function normalizeEmailHash(value = "") {
  return safeString(value || "", MAX_EMAIL_HASH_LENGTH)
    .toLowerCase()
    .replace(/[^a-f0-9]/g, "")
    .slice(0, MAX_EMAIL_HASH_LENGTH);
}

function normalizeUserId(value = "") {
  return safeString(value || "", MAX_USER_ID_LENGTH).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function normalizeSessionId(value = "") {
  return safeString(value || "", 128).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function normalizeIp(value = "") {
  let ip = safeString(value || "unknown", MAX_IP_LENGTH);

  if (!ip) return "unknown";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, MAX_IP_LENGTH);
  return ip || "unknown";
}

function normalizeRoute(value = "") {
  const raw = safeString(value || "unknown-route", MAX_ROUTE_LENGTH * 2);

  if (!raw) return "unknown-route";

  const cleaned = raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, MAX_ROUTE_LENGTH);

  return cleaned || "unknown-route";
}

function getRouteGroup(route = "") {
  const normalized = normalizeRoute(route);

  if (!normalized || normalized === "unknown-route") {
    return "unknown";
  }

  const segments = normalized.split("/").filter(Boolean);
  if (!segments.length) {
    return "root";
  }

  return safeString(segments.slice(0, 2).join("/"), MAX_ROUTE_GROUP_LENGTH);
}

function normalizeEventId(value = "") {
  return safeString(value || "", MAX_EVENT_ID_LENGTH).replace(/[^a-zA-Z0-9._:-]/g, "");
}

function normalizeFingerprint(value = "") {
  return safeString(value || "", MAX_FINGERPRINT_LENGTH)
    .toLowerCase()
    .replace(/[^a-f0-9]/g, "")
    .slice(0, MAX_FINGERPRINT_LENGTH);
}

function sanitizeMetadata(value, depth = 0) {
  if (depth > MAX_METADATA_DEPTH) {
    return "[max-depth]";
  }

  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value === "string") {
    return safeString(value, MAX_METADATA_STRING_LENGTH);
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_METADATA_ARRAY_ITEMS)
      .map((item) => sanitizeMetadata(item, depth + 1));
  }

  if (isPlainObject(value)) {
    const output = {};
    const entries = Object.entries(value).slice(0, MAX_METADATA_ITEMS);

    for (const [key, val] of entries) {
      const safeKey = safeString(key, MAX_METADATA_KEY_LENGTH);
      if (safeKey) {
        output[safeKey] = sanitizeMetadata(val, depth + 1);
      }
    }

    return output;
  }

  return safeString(value, 500);
}

function getRequiredEnv(env, name, maxLength = 10000) {
  return safeString(env?.[name] || "", maxLength);
}

function hasFirebaseAdminEnv(env) {
  return Boolean(
    getRequiredEnv(env, "FIREBASE_PROJECT_ID", 200) &&
      getRequiredEnv(env, "FIREBASE_CLIENT_EMAIL", 500) &&
      getRequiredEnv(env, "FIREBASE_PRIVATE_KEY", 20000)
  );
}

/* -------------------- IDS / HASHING -------------------- */

function createEventId() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);

  const randomHex = Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  return normalizeEventId(`sec_${Date.now()}_${randomHex}`);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(input = "") {
  const bytes = new TextEncoder().encode(String(input || ""));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

async function deriveEmailHash(email = "", providedHash = "") {
  const normalizedProvided = normalizeEmailHash(providedHash);
  if (normalizedProvided) return normalizedProvided;

  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return "";

  return (await sha256Hex(normalizedEmail)).slice(0, MAX_EMAIL_HASH_LENGTH);
}

async function deriveIpHash(ip = "") {
  const normalizedIp = normalizeIp(ip);
  if (!normalizedIp || normalizedIp === "unknown") {
    return "";
  }

  return (await sha256Hex(normalizedIp)).slice(0, 32);
}

async function buildEventFingerprint({
  type = "",
  userId = "",
  emailHash = "",
  ipHash = "",
  route = "",
  source = ""
}) {
  return normalizeFingerprint(
    (
      await sha256Hex(
        [
          safeString(type, 60),
          normalizeUserId(userId),
          normalizeEmailHash(emailHash),
          safeString(ipHash, 64),
          normalizeRoute(route),
          safeString(source, 50)
        ].join("|")
      )
    ).slice(0, MAX_FINGERPRINT_LENGTH)
  );
}

function getSeverityScore(level) {
  if (level === "critical") return 90;
  if (level === "error") return 70;
  if (level === "warning") return 40;
  return 10;
}

function deriveEventAction(level, metadataInput = {}, data = {}) {
  const explicitAction = safeEventAction(
    metadataInput?.action || data?.action || "",
    ""
  );

  if (explicitAction) return explicitAction;

  if (level === "critical") return "contain";
  if (level === "error") return "observe";
  if (level === "warning") return "observe";
  return "observe";
}

function extractSessionId(metadataInput = {}, sanitizedMetadata = {}) {
  return normalizeSessionId(
    metadataInput?.sessionId ||
      sanitizedMetadata?.sessionId ||
      metadataInput?.client?.sessionId ||
      ""
  );
}

/* -------------------- OAUTH -------------------- */

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
  const clientEmail = getRequiredEnv(env, "FIREBASE_CLIENT_EMAIL", 500);
  const privateKey = getRequiredEnv(env, "FIREBASE_PRIVATE_KEY", 20000).replace(/\\n/g, "\n");

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

/* -------------------- FIRESTORE SERIALIZATION -------------------- */

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
    if (!Number.isFinite(value)) {
      return { nullValue: null };
    }

    if (Number.isInteger(value)) {
      return { integerValue: String(value) };
    }

    return { doubleValue: value };
  }

  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map((item) => toFirestoreValue(item))
      }
    };
  }

  if (isPlainObject(value)) {
    const fields = {};
    for (const [key, val] of Object.entries(value)) {
      const safeKey = safeString(key, MAX_METADATA_KEY_LENGTH);
      if (safeKey) {
        fields[safeKey] = toFirestoreValue(val);
      }
    }

    return {
      mapValue: { fields }
    };
  }

  return { stringValue: safeString(value, 500) };
}

function toFirestoreDocumentFields(data) {
  const fields = {};

  for (const [key, value] of Object.entries(data)) {
    const safeKey = safeString(key, MAX_METADATA_KEY_LENGTH);
    if (safeKey) {
      fields[safeKey] = toFirestoreValue(value);
    }
  }

  return fields;
}

async function writeFirestoreDocument(env, collectionName, documentId, payload, retry = true) {
  const projectId = getRequiredEnv(env, "FIREBASE_PROJECT_ID", 200);
  const accessToken = await getAccessToken(env);

  const url =
    `${FIRESTORE_BASE_URL}/projects/${encodeURIComponent(projectId)}` +
    `/databases/(default)/documents/${encodeURIComponent(collectionName)}` +
    `?documentId=${encodeURIComponent(documentId)}`;

  const response = await fetch(url, {
    method: "POST",
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

    if ((response.status === 401 || response.status === 403) && retry) {
      clearAccessTokenCache();
      return writeFirestoreDocument(env, collectionName, documentId, payload, false);
    }

    throw new Error(
      `Firestore write failed: ${response.status} ${safeString(errorText, 500)}`
    );
  }

  return true;
}

/* -------------------- MAIN -------------------- */

export async function writeSecurityLog(data = {}) {
  try {
    const env = data?.env || null;

    if (!env || !hasFirebaseAdminEnv(env)) {
      console.error("Security log writer missing Cloudflare env credentials.");
      return false;
    }

    const type = safeString(data.type || "unknown", MAX_TYPE_LENGTH).toLowerCase();
    const level = safeLevel(data.level);
    const message = safeString(data.message || "", MAX_MESSAGE_LENGTH);

    const email = normalizeEmail(data.email || "");
    const emailHash = await deriveEmailHash(email, data.emailHash || "");
    const userId = normalizeUserId(data.userId || "");
    const ip = normalizeIp(data.ip || "unknown");
    const ipHash = await deriveIpHash(ip);

    const route = normalizeRoute(data.route || "unknown-route");
    const routeGroup = getRouteGroup(route);

    const metadataInput = isPlainObject(data.metadata) ? data.metadata : {};
    const metadata = sanitizeMetadata(metadataInput);

    const source = safeString(
      metadataInput?.source || data.source || "unspecified",
      MAX_SOURCE_LENGTH
    ).toLowerCase();

    const eventId =
      normalizeEventId(data.eventId || createEventId()) || createEventId();

    const severityScore = safeInt(
      data.severityScore,
      getSeverityScore(level),
      0,
      100
    );

    const fingerprint =
      normalizeFingerprint(data.fingerprint || "") ||
      (await buildEventFingerprint({
        type,
        userId,
        emailHash,
        ipHash,
        route,
        source
      }));

    const includeRawIdentity = data.includeRawIdentity === true;
    const sessionId = extractSessionId(metadataInput, metadata);
    const eventAction = deriveEventAction(level, metadataInput, data);
    const now = Date.now();

    const log = {
      eventId,
      type,
      level,
      severityScore,
      message,
      email: includeRawIdentity ? email : "",
      emailHash,
      userId,
      ip: includeRawIdentity ? ip : "",
      ipHash,
      route,
      routeGroup,
      source,
      fingerprint,
      metadata,
      createdAtMs: now,
      createdAtIso: new Date(now).toISOString()
    };

    await writeFirestoreDocument(env, "securityLogs", eventId, log);

    try {
      await appendSecurityEvent(env, {
        type,
        severity: level,
        action: eventAction,
        route,
        ip: includeRawIdentity ? ip : "",
        userId,
        reason: type,
        message,
        metadata: {
          eventId,
          routeGroup,
          source,
          fingerprint,
          severityScore,
          sessionId: sessionId || ""
        }
      });
    } catch (eventStoreError) {
      console.error("appendSecurityEvent failed:", eventStoreError);
    }

    try {
      await updateSecurityState({
        env,
        event: {
          type,
          level,
          userId,
          emailHash,
          ipHash,
          sessionId,
          routeGroup,
          source
        }
      });
    } catch (stateError) {
      console.error("updateSecurityState failed:", stateError);
    }

    return true;
  } catch (error) {
    console.error("writeSecurityLog failed:", error);
    return false;
  }
}
