import {
  doc,
  getDoc,
  serverTimestamp,
  setDoc,
  updateDoc
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { db } from "./firestore-config.js";

const DEFAULT_DISPLAY_NAME = "Explorer";
const MAX_DISPLAY_NAME_LENGTH = 30;
const MAX_PHOTO_URL_LENGTH = 500;
const MAX_EMAIL_LENGTH = 120;

function sanitizeDisplayName(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._ ]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_DISPLAY_NAME_LENGTH);
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .slice(0, MAX_EMAIL_LENGTH);
}

function isValidEmailLike(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ""));
}

function sanitizePhotoURL(value) {
  return String(value || "").trim().slice(0, MAX_PHOTO_URL_LENGTH);
}

function safeExistingString(value) {
  return typeof value === "string" ? value : "";
}

function buildCreatePayload(user) {
  const safeDisplayName = sanitizeDisplayName(user?.displayName) || DEFAULT_DISPLAY_NAME;
  const safeEmail = normalizeEmail(user?.email);
  const safePhotoURL = sanitizePhotoURL(user?.photoURL);

  return {
    uid: String(user.uid),
    displayName: safeDisplayName,
    email: isValidEmailLike(safeEmail) ? safeEmail : "",
    photoURL: safePhotoURL,
    role: "user",
    isProfileComplete: false,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };
}

function buildSafeUpdatePayload(existingData, user) {
  const updates = {};

  const safeDisplayName = sanitizeDisplayName(user?.displayName) || DEFAULT_DISPLAY_NAME;
  const safePhotoURL = sanitizePhotoURL(user?.photoURL);
  const safeEmail = normalizeEmail(user?.email);

  if (safeExistingString(existingData.displayName) !== safeDisplayName) {
    updates.displayName = safeDisplayName;
  }

  if (safeExistingString(existingData.photoURL) !== safePhotoURL) {
    updates.photoURL = safePhotoURL;
  }

  // Only repair email if it is missing/blank in Firestore and user auth has a valid-looking email.
  if (
    !safeExistingString(existingData.email) &&
    isValidEmailLike(safeEmail)
  ) {
    updates.email = safeEmail;
  }

  return updates;
}

export async function ensureUserProfile(user) {
  if (!user?.uid) {
    return;
  }

  const userRef = doc(db, "users", user.uid);

  let userSnap;
  try {
    userSnap = await getDoc(userRef);
  } catch (error) {
    console.error("Failed to read user profile:", error);
    return;
  }

  if (!userSnap.exists()) {
    const createPayload = buildCreatePayload(user);

    try {
      await setDoc(userRef, createPayload);
    } catch (error) {
      console.error("Failed to create user profile:", error);
    }

    return;
  }

  const existingData = userSnap.data() || {};
  const updates = buildSafeUpdatePayload(existingData, user);

  if (Object.keys(updates).length === 0) {
    return;
  }

  updates.updatedAt = serverTimestamp();

  try {
    await updateDoc(userRef, updates);
  } catch (error) {
    console.error("Failed to update user profile:", error);
  }
}
