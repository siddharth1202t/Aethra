import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";

let adminDb = null;

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error",
  "critical"
]);

const MAX_TYPE_LENGTH = 60;
const MAX_MESSAGE_LENGTH = 500;
const MAX_EMAIL_LENGTH = 200;
const MAX_USER_ID_LENGTH = 128;
const MAX_IP_LENGTH = 100;
const MAX_ROUTE_LENGTH = 150;
const MAX_METADATA_STRING_LENGTH = 1000;
const MAX_METADATA_KEY_LENGTH = 100;
const MAX_METADATA_ITEMS = 30;
const MAX_METADATA_ARRAY_ITEMS = 25;
const MAX_METADATA_DEPTH = 4;

function getAdminDb() {
  if (adminDb) {
    return adminDb;
  }

  if (!getApps().length) {
    initializeApp({
      credential: cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n")
      })
    });
  }

  adminDb = getFirestore();
  return adminDb;
}

function safeString(value, maxLength = 300) {
  return String(value || "").slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeLevel(level) {
  const normalized = safeString(level || "warning", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "warning";
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
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
      output[safeString(key, MAX_METADATA_KEY_LENGTH)] = sanitizeMetadata(val, depth + 1);
    }

    return output;
  }

  return safeString(value, 500);
}

export async function writeSecurityLog(data = {}) {
  try {
    const db = getAdminDb();

    const type = safeString(data.type || "unknown", MAX_TYPE_LENGTH);
    const level = safeLevel(data.level);
    const message = safeString(data.message || "", MAX_MESSAGE_LENGTH);
    const email = safeString(data.email || "", MAX_EMAIL_LENGTH);
    const userId = safeString(data.userId || "", MAX_USER_ID_LENGTH);
    const ip = safeString(data.ip || "unknown", MAX_IP_LENGTH);
    const route = safeString(data.route || "unknown-route", MAX_ROUTE_LENGTH);
    const metadata = sanitizeMetadata(data.metadata || {});

    const log = {
      type,
      level,
      message,
      email,
      userId,
      ip,
      route,
      metadata,
      createdAt: FieldValue.serverTimestamp(),
      createdAtMs: Date.now()
    };

    await db.collection("securityLogs").add(log);
    return true;
  } catch (error) {
    console.error("writeSecurityLog failed:", error);
    return false;
  }
}
