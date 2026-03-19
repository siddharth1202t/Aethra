import crypto from "node:crypto";
import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { updateSecurityState } from "./_security-state-manager.js";

let adminDb = null;
let adminInitFailed = false;

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error",
  "critical"
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

function safeString(value, maxLength = 300) {
  return String(value || "")
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

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function normalizeEmail(value = "") {
  const email = safeString(value || "", MAX_EMAIL_LENGTH).toLowerCase();
  if (!email) return "";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return "";
  }
  return email;
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

function getRequiredEnv(name) {
  return safeString(process.env[name] || "", 5000);
}

function hasFirebaseAdminEnv() {
  return Boolean(
    getRequiredEnv("FIREBASE_PROJECT_ID") &&
    getRequiredEnv("FIREBASE_CLIENT_EMAIL") &&
    safeString(process.env.FIREBASE_PRIVATE_KEY || "", 10000)
  );
}

function createEventId() {
  return normalizeEventId(
    `sec_${Date.now()}_${crypto.randomBytes(6).toString("hex")}`
  );
}

function sha256Hex(input = "") {
  return crypto
    .createHash("sha256")
    .update(String(input || ""))
    .digest("hex");
}

function deriveEmailHash(email = "", providedHash = "") {
  const normalizedProvided = normalizeEmailHash(providedHash);
  if (normalizedProvided) {
    return normalizedProvided;
  }

  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    return "";
  }

  return sha256Hex(normalizedEmail).slice(0, MAX_EMAIL_HASH_LENGTH);
}

function deriveIpHash(ip = "") {
  const normalizedIp = normalizeIp(ip);
  if (!normalizedIp || normalizedIp === "unknown") {
    return "";
  }

  return sha256Hex(normalizedIp).slice(0, 32);
}

function buildEventFingerprint({
  type = "",
  userId = "",
  emailHash = "",
  ipHash = "",
  route = "",
  source = ""
}) {
  return normalizeFingerprint(
    sha256Hex(
      [
        safeString(type, 60),
        normalizeUserId(userId),
        normalizeEmailHash(emailHash),
        safeString(ipHash, 64),
        normalizeRoute(route),
        safeString(source, 50)
      ].join("|")
    ).slice(0, MAX_FINGERPRINT_LENGTH)
  );
}

function getSeverityScore(level) {
  if (level === "critical") return 90;
  if (level === "error") return 70;
  if (level === "warning") return 40;
  return 10;
}

function getAdminDb() {
  if (adminDb) {
    return adminDb;
  }

  if (adminInitFailed) {
    return null;
  }

  try {
    if (!hasFirebaseAdminEnv()) {
      adminInitFailed = true;
      console.error("Firebase Admin env vars are missing for security log writer.");
      return null;
    }

    if (!getApps().length) {
      initializeApp({
        credential: cert({
          projectId: getRequiredEnv("FIREBASE_PROJECT_ID"),
          clientEmail: getRequiredEnv("FIREBASE_CLIENT_EMAIL"),
          privateKey: String(process.env.FIREBASE_PRIVATE_KEY || "")
            .replace(/\\n/g, "\n")
            .trim()
        })
      });
    }

    adminDb = getFirestore();
    return adminDb;
  } catch (error) {
    adminInitFailed = true;
    console.error("Firebase Admin initialization failed:", error);
    return null;
  }
}

export async function writeSecurityLog(data = {}) {
  try {
    const db = getAdminDb();

    if (!db) {
      return false;
    }

    const type = safeString(data.type || "unknown", MAX_TYPE_LENGTH).toLowerCase();
    const level = safeLevel(data.level);
    const message = safeString(data.message || "", MAX_MESSAGE_LENGTH);

    const email = normalizeEmail(data.email || "");
    const emailHash = deriveEmailHash(email, data.emailHash || "");
    const userId = normalizeUserId(data.userId || "");
    const ip = normalizeIp(data.ip || "unknown");
    const ipHash = deriveIpHash(ip);

    const route = normalizeRoute(data.route || "unknown-route");
    const routeGroup = getRouteGroup(route);

    const metadataInput = isPlainObject(data.metadata) ? data.metadata : {};
    const metadata = sanitizeMetadata(metadataInput);

    const source = safeString(
      metadataInput?.source || data.source || "unspecified",
      MAX_SOURCE_LENGTH
    ).toLowerCase();

    const eventId = normalizeEventId(data.eventId || createEventId()) || createEventId();
    const severityScore = safeInt(
      data.severityScore,
      getSeverityScore(level),
      0,
      100
    );

    const fingerprint =
      normalizeFingerprint(data.fingerprint || "") ||
      buildEventFingerprint({
        type,
        userId,
        emailHash,
        ipHash,
        route,
        source
      });

    const log = {
      eventId,
      type,
      level,
      severityScore,
      message,
      email,
      emailHash,
      userId,
      ip,
      ipHash,
      route,
      routeGroup,
      source,
      fingerprint,
      metadata,
      createdAt: FieldValue.serverTimestamp(),
      createdAtMs: Date.now()
    };

    await db.collection("securityLogs").doc(eventId).set(log, { merge: false });

    await updateSecurityState(db, {
      type,
      level,
      userId,
      emailHash,
      ipHash,
      sessionId: safeString(
        metadataInput?.sessionId ||
        metadata?.sessionId ||
        metadataInput?.client?.sessionId ||
        "",
        128
      ),
      routeGroup,
      source
    });

    return true;
  } catch (error) {
    console.error("writeSecurityLog failed:", error);
    return false;
  }
}
