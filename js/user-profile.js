import { doc, getDoc, serverTimestamp, setDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { db } from "./firestore-config.js";

function sanitizeDisplayName(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._ ]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 20);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function sanitizePhotoURL(value) {
  return String(value || "").trim().slice(0, 500);
}

export async function ensureUserProfile(user) {
  if (!user) return;

  const userRef = doc(db, "users", user.uid);
  const userSnap = await getDoc(userRef);

  if (!userSnap.exists()) {
    await setDoc(userRef, {
      uid: user.uid,
      displayName: sanitizeDisplayName(user.displayName) || "Explorer",
      email: normalizeEmail(user.email),
      photoURL: sanitizePhotoURL(user.photoURL),
      role: "user",
      isProfileComplete: false,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    });
  }
}
