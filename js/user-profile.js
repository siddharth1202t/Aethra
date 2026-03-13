import { doc, getDoc, serverTimestamp, setDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { db } from "./firestore-config.js";

export async function ensureUserProfile(user) {
  if (!user) return;

  const userRef = doc(db, "users", user.uid);
  const userSnap = await getDoc(userRef);

  if (!userSnap.exists()) {
    await setDoc(userRef, {
      uid: user.uid,
      displayName: user.displayName || "Explorer",
      email: user.email || "",
      photoURL: user.photoURL || "",
      role: "user",
      isProfileComplete: false,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    });
  }
}
