import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";

let adminDb = null;

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error",
  "critical"
]);

const MAX_TYPE_LENGTH = 50;
const MAX_MESSAGE_LENGTH = 500;
const MAX_EMAIL_LENGTH = 200;
const MAX_USER_ID_LENGTH = 128;
const MAX_IP_LENGTH = 100;
const MAX_ROUTE_LENGTH = 120;
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
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n");

    if (!projectId || !clientEmail || !privateKey) {
      throw new Error("Missing Firebase Admin environment variables.");
    }

    initializeApp({
      credential: cert({
        projectId,
        clientEmail,
        privateKey
      })
    });
  }

  adminDb = getFirestore();
  return adminDb;
}

function safeString(value, maxLength = 300) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value).slice(0, maxLength);
}

function safeLevel(level) {
  const normalized = safeString(level || "warning", 20).toLowerCase();
  return ALLOWED_LEVELS.has(normalized) ? normalized : "warning";
}

function sanitizePrimitive(value) {
  if (
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return typeof value === "string"
      ? safeString(value, MAX_METADATA_STRING_LENGTH)
      : value;
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }

  return null;
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

  const primitive = sanitizePrimitive(value);
  if (
    primitive !== null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return primitive;
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

    const log = {
      type: safeString(data.type || "unknown", MAX_TYPE_LENGTH),
      message: safeString(data.message || "", MAX_MESSAGE_LENGTH),
      email: safeString(data.email || "", MAX_EMAIL_LENGTH),
      userId: safeString(data.userId || "", MAX_USER_ID_LENGTH),
      ip: safeString(data.ip || "", MAX_IP_LENGTH),
      route: safeString(data.route || "", MAX_ROUTE_LENGTH),
      level: safeLevel(data.level),
      metadata: sanitizeMetadata(data.metadata || {}),
      createdAt: FieldValue.serverTimestamp()
    };

    await db.collection("securityLogs").add(log);
  } catch (error) {
    console.error("Security log write failed:", error);
  }
}
