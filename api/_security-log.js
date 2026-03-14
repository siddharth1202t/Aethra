import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";

let adminDb = null;

function getAdminDb() {
  if (adminDb) return adminDb;

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
  if (!value) return "";
  return String(value).slice(0, maxLength);
}

export async function writeSecurityLog(data = {}) {
  try {
    const db = getAdminDb();

    const log = {
      type: safeString(data.type || "unknown", 50),
      message: safeString(data.message || "", 500),
      email: safeString(data.email || "", 200),
      ip: safeString(data.ip || "", 100),
      route: safeString(data.route || "", 100),
      metadata: data.metadata || {},
      level: data.level || "warning",
      createdAt: FieldValue.serverTimestamp()
    };

    await db.collection("securityLogs").add(log);

  } catch (error) {
    console.error("Security log write failed:", error);
  }
}
