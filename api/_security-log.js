import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";

let adminDb = null;

const ALLOWED_LEVELS = new Set([
  "info",
  "warning",
  "error",
  "critical"
]);

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

function sanitizeMetadata(value, depth = 0) {
  if (depth > 4) {
    return "[max-depth]";
  }

  if (value === null || value === undefined) {
    return null;
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return typeof value === "string" ? safeString(value, 1000) : value;
  }

  if (Array.isArray(value)) {
    return value.slice(0, 25).map((item) => sanitizeMetadata(item, depth + 1));
  }

  if (typeof value === "object") {
    const output = {};
    const entries = Object.entries(value).slice(0, 30);

    for (const [key, val] of entries) {
      output[safeString(key, 100)] = sanitizeMetadata(val, depth + 1);
    }

    return output;
  }

  return safeString(value, 500);
}

export async function writeSecurityLog(data = {}) {
  try {
    const db = getAdminDb();

    const log = {
      type: safeString(data.type || "unknown", 50),
      message: safeString(data.message || "", 500),
      email: safeString(data.email || "", 200),
      userId: safeString(data.userId || "", 128),
      ip: safeString(data.ip || "", 100),
      route: safeString(data.route || "", 120),
      level: safeLevel(data.level),
      metadata: sanitizeMetadata(data.metadata || {}),
      createdAt: FieldValue.serverTimestamp()
    };

    await db.collection("securityLogs").add(log);
  } catch (error) {
    console.error("Security log write failed:", error);
  }
}
