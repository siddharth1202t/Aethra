import {
  getAuth,
  onAuthStateChanged,
  reload,
  sendEmailVerification
} from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";

const RESEND_COOLDOWN_SECONDS = 60;
const auth = getAuth(app);

// Elements
const verifyCard = document.getElementById("verifyCard");
const resendBtn = document.getElementById("resendBtn");
const messageBox = document.getElementById("messageBox");

let resendCountdown = null;
let resendRemaining = 0;
let authHandled = false;
let resendInProgress = false;

// Continue URL after verification
const CONTINUE_URL =
  window.location.hostname.includes("localhost")
    ? "http://localhost:5173/login.html"
    : "https://YOUR_PRODUCTION_DOMAIN/login.html"; // Replace with your domain

/* ---------------- HELPERS ---------------- */
function goTo(page) {
  window.location.replace(page);
}

function showMessage(text, type = "error") {
  if (!messageBox) return;
  messageBox.textContent = String(text || "").trim();
  messageBox.className = `msg show ${type === "success" ? "success" : "error"}`;
}

function clearMessage() {
  if (!messageBox) return;
  messageBox.textContent = "";
  messageBox.className = "msg";
}

function setPageVisible() {
  if (!verifyCard) return;
  verifyCard.style.visibility = "visible";
  window.requestAnimationFrame(() => {
    verifyCard.style.opacity = "1";
    verifyCard.style.transform = "translateY(0)";
  });
}

function clearResendCountdown() {
  if (resendCountdown) {
    clearInterval(resendCountdown);
    resendCountdown = null;
  }
}

function setResendCooldown(seconds = RESEND_COOLDOWN_SECONDS) {
  if (!resendBtn) return;

  resendRemaining = Math.max(0, Number(seconds) || 0);
  resendBtn.disabled = true;
  resendBtn.textContent = `Resend in ${resendRemaining}s`;

  clearResendCountdown();
  resendCountdown = setInterval(() => {
    resendRemaining -= 1;
    if (resendRemaining <= 0) {
      clearResendCountdown();
      resendBtn.disabled = false;
      resendBtn.textContent = resendBtn.dataset.originalText || "Resend Verification Email";
      return;
    }
    resendBtn.textContent = `Resend in ${resendRemaining}s`;
  }, 1000);
}

async function refreshCurrentUser(user) {
  if (!user) return null;
  await reload(user);
  return auth.currentUser;
}

/* ---------------- AUTH STATE ---------------- */
onAuthStateChanged(auth, async (user) => {
  if (authHandled) return;

  if (!user) {
    authHandled = true;
    goTo("login.html");
    return;
  }

  try {
    const refreshedUser = await refreshCurrentUser(user);
    if (refreshedUser?.emailVerified) {
      authHandled = true;
      goTo(CONTINUE_URL);
      return;
    }

    authHandled = true;
    setPageVisible();
  } catch (error) {
    console.error("Verification auth refresh failed:", error);
    authHandled = true;
    setPageVisible();
    showMessage("Could not refresh your account status. Please try again.", "error");
  }
});

/* ---------------- ACTIONS ---------------- */
resendBtn?.addEventListener("click", async () => {
  if (resendInProgress || resendRemaining > 0) return;

  const user = auth.currentUser;
  if (!user) {
    goTo("login.html");
    return;
  }

  resendInProgress = true;
  try {
    clearMessage();
    resendBtn.disabled = true;
    resendBtn.textContent = "Sending...";

    await sendEmailVerification(user, { url: CONTINUE_URL });
    showMessage("Verification email sent. Check your inbox!", "success");
    setResendCooldown();
  } catch (error) {
    console.error("Resend verification failed:", error);
    showMessage("Could not resend verification email. Try again.", "error");
  } finally {
    resendInProgress = false;
    resendBtn.disabled = false;
    resendBtn.textContent = resendBtn.dataset.originalText || "Resend Verification Email";
  }
});

/* ---------------- AUTO-REDIRECT ---------------- */
async function checkVerifiedPeriodically() {
  const user = auth.currentUser;
  if (!user) return;

  try {
    const refreshedUser = await refreshCurrentUser(user);
    if (refreshedUser?.emailVerified) {
      goTo(CONTINUE_URL);
      return;
    }
  } catch (err) {
    console.error("Periodic verification check failed:", err);
  }

  setTimeout(checkVerifiedPeriodically, 3000); // check every 3s
}

document.addEventListener("DOMContentLoaded", () => {
  if (verifyCard) verifyCard.style.visibility = "hidden";
  if (resendBtn) resendBtn.dataset.originalText = resendBtn.textContent || "Resend Verification Email";
  checkVerifiedPeriodically();
});
