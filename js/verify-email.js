import { getAuth, onAuthStateChanged, reload, sendEmailVerification } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { app } from "./firestore-config.js";

const RESEND_COOLDOWN_SECONDS = 60;
const auth = getAuth(app);

const verifyCard = document.getElementById("verifyCard");
const resendBtn = document.getElementById("resendBtn");
const messageBox = document.getElementById("messageBox");
const statusIcon = document.getElementById("statusIcon");
const subtext = document.getElementById("subtext");

let resendCountdown = null;
let resendRemaining = 0;
let resendInProgress = false;
let authHandled = false;

/* ---------------- HELPERS ---------------- */
function goTo(page) {
  window.location.replace(page);
}

function showMessage(text, type = "error") {
  messageBox.textContent = text;
  messageBox.className = `msg show ${type === "success" ? "success" : "error"}`;
}

function clearMessage() {
  messageBox.textContent = "";
  messageBox.className = "msg";
}

function setLoading(button, text) {
  if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
  button.disabled = true;
  button.textContent = text;
}

function clearLoading(button) {
  button.disabled = false;
  button.textContent = button.dataset.originalText || button.textContent;
}

function clearResendCountdown() {
  if (resendCountdown) clearInterval(resendCountdown);
  resendCountdown = null;
}

function setResendCooldown(seconds = RESEND_COOLDOWN_SECONDS) {
  resendRemaining = seconds;
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
  await reload(user);
  return auth.currentUser;
}

function setPageVisible() {
  verifyCard.style.visibility = "visible";
  window.requestAnimationFrame(() => {
    verifyCard.style.opacity = "1";
    verifyCard.style.transform = "translateY(0)";
  });
}

function showVerifiedState() {
  if (statusIcon) statusIcon.style.opacity = 1;
  if (subtext) subtext.textContent = "Your email is verified! Redirecting...";
  if (resendBtn) resendBtn.style.display = "none";
}

/* ---------------- AUTH CHECK ---------------- */
async function checkEmailVerification(user) {
  const refreshedUser = await refreshCurrentUser(user);
  if (refreshedUser?.emailVerified) {
    showVerifiedState();
    setTimeout(() => goTo("login.html"), 1500);
  }
}

onAuthStateChanged(auth, async (user) => {
  if (authHandled) return;

  if (!user) {
    authHandled = true;
    goTo("login.html");
    return;
  }

  authHandled = true;
  setPageVisible();

  // Poll email verification every 5 seconds
  const pollInterval = setInterval(async () => {
    const currentUser = auth.currentUser;
    if (!currentUser) return clearInterval(pollInterval);
    await checkEmailVerification(currentUser);
  }, 5000);
});

/* ---------------- RESEND EMAIL ---------------- */
resendBtn.addEventListener("click", async () => {
  if (resendInProgress || resendRemaining > 0) return;
  const user = auth.currentUser;
  if (!user) return goTo("login.html");

  resendInProgress = true;
  clearMessage();
  setLoading(resendBtn, "Sending...");

  try {
    await sendEmailVerification(user);
    showMessage("Verification email sent. Check your inbox.", "success");
    setResendCooldown();
  } catch (error) {
    console.error("Resend failed:", error);
    showMessage("Could not resend verification email. Try again.", "error");
  } finally {
    clearLoading(resendBtn);
    resendInProgress = false;
  }
});

/* ---------------- CLEANUP ---------------- */
window.addEventListener("beforeunload", () => {
  clearResendCountdown();
});
