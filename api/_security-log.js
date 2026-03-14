import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

function getAdminDb() {
  if (!getApps().length) {
    initializeApp({
      credential: cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n")
      })
    });
  }

  return getFirestore();
}

export async function writeSecurityLog(data) {
  try {
    const db = getAdminDb();

    await db.collection("securityLogs").add({
      type: data.type || "unknown",
      message: data.message || "",
      email: data.email || "",
      ip: data.ip || "",
      route: data.route || "",
      metadata: data.metadata || {},
      createdAt: new Date()
    });
  } catch (error) {
    console.error("Failed to write security log:", error);
  }
}
