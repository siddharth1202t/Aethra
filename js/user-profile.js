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
const MAX_UID_LENGTH = 128;

function safeString(value, maxLength = 300) {
  return String(value || "").trim().slice(0, maxLength);
}

function sanitizeDisplayName(value) {
  return safeString(value, MAX_DISPLAY_NAME_LENGTH)
    .normalize("NFKC")
    .replace(/[^a-zA-Z0-9._ ]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_DISPLAY_NAME_LENGTH);
}

function normalizeEmail(value) {
  return safeString(value, MAX_EMAIL_LENGTH).toLowerCase();
}

function isValidEmailLike(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || ""));
}

function sanitizePhotoURL(value) {
  const url = safeString(value, MAX_PHOTO_URL_LENGTH);

  if (!url) {
    return "";
  }

  try {
    const parsed = new URL(url);
    return /^https:$/i.test(parsed.protocol)
      ? parsed.toString().slice(0, MAX_PHOTO_URL_LENGTH)
      : "";
  } catch {
    return "";
  }
}

function safeExistingString(value) {
  return typeof value === "string" ? value : "";
}

function getSafeDisplayName(user) {
  return sanitizeDisplayName(user?.displayName) || DEFAULT_DISPLAY_NAME;
}

function getSafeEmail(user) {
  const safeEmail = normalizeEmail(user?.email);
  return isValidEmailLike(safeEmail) ? safeEmail : "";
}

function getSafePhotoURL(user) {
  return sanitizePhotoURL(user?.photoURL);
}

function buildCreatePayload(user) {
  const safeUid = safeString(user?.uid || "", MAX_UID_LENGTH);
  const safeEmail = getSafeEmail(user);

  if (!safeUid || !safeEmail) {
    return null;
  }

  return {
    uid: safeUid,
    displayName: getSafeDisplayName(user),
    email: safeEmail,
    photoURL: getSafePhotoURL(user),
    role: "user",
    isProfileComplete: false,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };
}

function buildSafeUpdatePayload(existingData, user) {
  const updates = {};

  const safeDisplayName = getSafeDisplayName(user);
  const safePhotoURL = getSafePhotoURL(user);
  const safeEmail = getSafeEmail(user);

  if (safeExistingString(existingData.displayName) !== safeDisplayName) {
    updates.displayName = safeDisplayName;
  }

  if (safeExistingString(existingData.photoURL) !== safePhotoURL) {
    updates.photoURL = safePhotoURL;
  }

  if (!safeExistingString(existingData.email) && safeEmail) {
    updates.email = safeEmail;
  }

  return updates;
}

export async function ensureUserProfile(user) {
  if (!user?.uid) {
    return { ok: false, reason: "missing_user_uid" };
  }

  const safeUid = safeString(user.uid, MAX_UID_LENGTH);
  if (!safeUid) {
    return { ok: false, reason: "invalid_user_uid" };
  }

  const userRef = doc(db, "users", safeUid);

  let userSnap;
  try {
    userSnap = await getDoc(userRef);
  } catch (error) {
    console.error("Failed to read user profile:", error);
    return { ok: false, reason: "read_failed" };
  }

  if (!userSnap.exists()) {
    const createPayload = buildCreatePayload(user);

    if (!createPayload) {
      return { ok: false, reason: "invalid_create_payload" };
    }

    try {
      await setDoc(userRef, createPayload);
      return { ok: true, action: "created" };
    } catch (error) {
      console.error("Failed to create user profile:", error);
      return { ok: false, reason: "create_failed" };
    }
  }

  const existingData = userSnap.data() || {};

  if (existingData.profileLocked === true) {
    return { ok: true, action: "skipped_locked_profile" };
  }

  const updates = buildSafeUpdatePayload(existingData, user);

  if (Object.keys(updates).length === 0) {
    return { ok: true, action: "no_changes" };
  }

  updates.updatedAt = serverTimestamp();

  try {
    await updateDoc(userRef, updates);
    return { ok: true, action: "updated" };
  } catch (error) {
    console.error("Failed to update user profile:", error);
    return { ok: false, reason: "update_failed" };
  }
}
