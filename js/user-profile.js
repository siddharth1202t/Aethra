import { doc, getDoc, serverTimestamp, setDoc, updateDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
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
  if (!user?.uid) return;

  const userRef = doc(db, "users", user.uid);
  const userSnap = await getDoc(userRef);

  const safeDisplayName = sanitizeDisplayName(user.displayName) || "Explorer";
  const safeEmail = normalizeEmail(user.email);
  const safePhotoURL = sanitizePhotoURL(user.photoURL);
  const emailVerified = Boolean(user.emailVerified);

  if (!userSnap.exists()) {
    await setDoc(userRef, {
      uid: user.uid,
      displayName: safeDisplayName,
      email: safeEmail,
      photoURL: safePhotoURL,
      role: "user",
      isProfileComplete: false,
      emailVerified,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    });
    return;
  }

  const existingData = userSnap.data() || {};
  const updates = {};

  if (existingData.displayName !== safeDisplayName) {
    updates.displayName = safeDisplayName;
  }

  if ((existingData.photoURL || "") !== safePhotoURL) {
    updates.photoURL = safePhotoURL;
  }

  if (existingData.emailVerified !== emailVerified) {
    updates.emailVerified = emailVerified;
  }

  if (Object.keys(updates).length > 0) {
    updates.updatedAt = serverTimestamp();
    await updateDoc(userRef, updates);
  }
}
