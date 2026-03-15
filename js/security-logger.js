import { collection, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { db } from "./firestore-config.js";

function safeString(value, maxLength = 300) {
  if (!value) return "";
  return String(value).slice(0, maxLength);
}

export async function writeSecurityLog(data = {}) {
  try {

    const log = {
      type: safeString(data.type || "unknown", 50),
      message: safeString(data.message || "", 500),
      email: safeString(data.email || "", 200),
      userId: safeString(data.userId || "", 200),
      userAgent: safeString(navigator.userAgent || "", 300),
      url: safeString(window.location.href || "", 500),
      createdAt: serverTimestamp()
    };

    await addDoc(collection(db, "securityLogs"), log);

  } catch (error) {
    console.error("Security log failed:", error);
  }
}
