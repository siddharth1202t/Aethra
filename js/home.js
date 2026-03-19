import { getAuth, signOut } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { doc, getDoc } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";
import { app, db } from "./firestore-config.js";
import { requireAuth } from "./auth-guard.js";

const auth = getAuth(app);

const shell = document.querySelector(".shell");
const topbar = document.querySelector(".topbar");
const heroCard = document.querySelector(".hero-card");
const sidePanel = document.querySelector(".side-panel");
const statBoxes = Array.from(document.querySelectorAll(".stat-box"));
const miniCards = Array.from(document.querySelectorAll(".mini-card"));
const quickBoxes = Array.from(document.querySelectorAll(".quick-box"));
const primaryBtn = document.querySelector(".primary-btn");
const secondaryBtn = document.querySelector(".secondary-btn");

const userRoleEl = document.getElementById("userRole");
const heroUsernameEl = document.getElementById("heroUsername");
const logoutBtn = document.getElementById("logoutBtn");
const devBtn = document.getElementById("devBtn");

let pageReady = false;
let logoutInProgress = false;
let actionsBound = false;
let parallaxBound = false;
let scrollBound = false;

/* ---------------- BASIC HELPERS ---------------- */

function goTo(page) {
  window.location.replace(page);
}

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function setPageVisible() {
  if (!shell || pageReady) {
    return;
  }

  shell.style.visibility = "visible";

  window.requestAnimationFrame(() => {
    shell.style.opacity = "1";
    shell.style.transform = "translateY(0)";
  });

  pageReady = true;
}

function setPageLoadingState() {
  if (!shell) {
    return;
  }

  shell.style.visibility = "visible";
  shell.style.opacity = "0";
  shell.style.transform = "translateY(10px)";
  shell.style.transition =
    "opacity 320ms ease, transform 320ms cubic-bezier(0.22, 1, 0.36, 1)";
}

function getBestDisplayName(user) {
  const directName = user?.displayName?.trim();
  const providerName = user?.providerData?.[0]?.displayName?.trim();
  const emailName = user?.email ? user.email.split("@")[0] : "";

  return directName || providerName || emailName || "Explorer";
}

function setDefaultUserUI(user) {
  if (heroUsernameEl) {
    heroUsernameEl.textContent = getBestDisplayName(user);
  }

  if (userRoleEl) {
    userRoleEl.textContent = "User";
  }

  if (devBtn) {
    devBtn.style.display = "none";
  }
}

/* ---------------- ROLE HYDRATION ---------------- */

async function hydrateRole(user) {
  if (!user?.uid) {
    return;
  }

  try {
    const userRef = doc(db, "users", user.uid);
    const userSnap = await getDoc(userRef);

    if (!userSnap.exists()) {
      return;
    }

    const userData = userSnap.data() || {};
    const role = String(userData.role || "").toLowerCase();
    const isDeveloper = role === "developer";

    if (userRoleEl) {
      userRoleEl.textContent = isDeveloper ? "Developer" : "User";
    }

    if (devBtn) {
      devBtn.style.display = isDeveloper ? "block" : "none";
    }
  } catch (error) {
    console.error("Role hydration failed:", error);
  }
}

/* ---------------- PREMIUM INTERACTIONS ---------------- */

function attachTilt(element, options = {}) {
  if (!element || prefersReducedMotion()) {
    return;
  }

  const { maxRotate = 6, scale = 1.01, perspective = 900 } = options;
  let rect = null;

  function onEnter() {
    rect = element.getBoundingClientRect();
    element.style.willChange = "transform";
    element.style.transition =
      "transform 180ms ease, box-shadow 260ms ease, border-color 260ms ease";
  }

  function onMove(event) {
    if (!rect) {
      rect = element.getBoundingClientRect();
    }

    const px = (event.clientX - rect.left) / rect.width;
    const py = (event.clientY - rect.top) / rect.height;

    const rotateY = (px - 0.5) * maxRotate * 2;
    const rotateX = (0.5 - py) * maxRotate * 2;

    element.style.transform = `
      perspective(${perspective}px)
      rotateX(${rotateX.toFixed(2)}deg)
      rotateY(${rotateY.toFixed(2)}deg)
      scale(${scale})
    `;
  }

  function onLeave() {
    rect = null;
    element.style.transition =
      "transform 320ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 260ms ease, border-color 260ms ease";
    element.style.transform = "";

    window.setTimeout(() => {
      element.style.willChange = "auto";
    }, 320);
  }

  element.addEventListener("pointerenter", onEnter);
  element.addEventListener("pointermove", onMove);
  element.addEventListener("pointerleave", onLeave);
}

function enhanceButtons() {
  [primaryBtn, secondaryBtn, logoutBtn, devBtn].forEach((button) => {
    if (!button || prefersReducedMotion()) {
      return;
    }

    button.addEventListener("pointerdown", () => {
      button.style.transform = "translateY(0) scale(0.985)";
    });

    button.addEventListener("pointerup", () => {
      button.style.transform = "";
    });

    button.addEventListener("pointerleave", () => {
      button.style.transform = "";
    });
  });
}

function initPremiumInteractions() {
  attachTilt(heroCard, { maxRotate: 4, scale: 1.008, perspective: 1100 });
  attachTilt(sidePanel, { maxRotate: 4, scale: 1.01, perspective: 950 });

  statBoxes.forEach((box) => {
    attachTilt(box, { maxRotate: 5, scale: 1.015, perspective: 850 });
  });

  miniCards.forEach((card) => {
    attachTilt(card, { maxRotate: 4, scale: 1.01, perspective: 850 });
  });

  quickBoxes.forEach((box) => {
    attachTilt(box, { maxRotate: 4, scale: 1.01, perspective: 850 });
  });

  enhanceButtons();
}

function updateTopbarOnScroll() {
  if (!topbar) {
    return;
  }

  const scrolled = window.scrollY > 20;

  if (scrolled) {
    topbar.style.background =
      "linear-gradient(180deg, rgba(255,255,255,0.075), rgba(255,255,255,0.045))";
    topbar.style.borderColor = "rgba(255,255,255,0.14)";
    topbar.style.boxShadow =
      "0 18px 42px rgba(0,0,0,0.28), inset 0 1px 0 rgba(255,255,255,0.04)";
  } else {
    topbar.style.background =
      "linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.035))";
    topbar.style.borderColor = "rgba(255,255,255,0.1)";
    topbar.style.boxShadow =
      "0 16px 38px rgba(0,0,0,0.24), inset 0 1px 0 rgba(255,255,255,0.04)";
  }
}

function initHeroParallax() {
  if (prefersReducedMotion() || parallaxBound) {
    return;
  }

  const aurora = document.querySelector(".aurora");
  if (!aurora) {
    return;
  }

  const onMove = (event) => {
    const x = (event.clientX / window.innerWidth - 0.5) * 12;
    const y = (event.clientY / window.innerHeight - 0.5) * 12;

    aurora.style.transform = `translate3d(${x}px, ${y}px, 0)`;

    if (heroCard) {
      const tiltX = clamp((0.5 - event.clientY / window.innerHeight) * 3, -3, 3);
      const tiltY = clamp((event.clientX / window.innerWidth - 0.5) * 3, -3, 3);

      heroCard.style.transform = `
        perspective(1100px)
        rotateX(${tiltX.toFixed(2)}deg)
        rotateY(${tiltY.toFixed(2)}deg)
      `;
    }
  };

  const onLeave = () => {
    aurora.style.transform = "";
    if (heroCard) {
      heroCard.style.transform = "";
    }
  };

  window.addEventListener("pointermove", onMove, { passive: true });
  window.addEventListener("pointerleave", onLeave, { passive: true });
  parallaxBound = true;
}

/* ---------------- ACTIONS ---------------- */

function bindActions() {
  if (actionsBound) {
    return;
  }

  devBtn?.addEventListener("click", () => {
    goTo("developer.html");
  });

  logoutBtn?.addEventListener("click", async () => {
    if (logoutInProgress) {
      return;
    }

    logoutInProgress = true;

    try {
      if (logoutBtn) {
        logoutBtn.disabled = true;
        logoutBtn.textContent = "Logging out...";
      }

      if (devBtn) {
        devBtn.disabled = true;
      }

      await signOut(auth);
    } catch (error) {
      console.error("Logout failed:", error);
    } finally {
      goTo("login.html");
    }
  });

  primaryBtn?.addEventListener("click", () => {
    // Placeholder until chat page is connected
    console.log("Start Chatting clicked");
  });

  secondaryBtn?.addEventListener("click", () => {
    // Placeholder until character page/section is connected
    console.log("Explore Characters clicked");
  });

  actionsBound = true;
}

/* ---------------- INIT ---------------- */

async function initHomePage() {
  setPageLoadingState();
  bindActions();
  initPremiumInteractions();
  initHeroParallax();

  if (!scrollBound) {
    updateTopbarOnScroll();
    window.addEventListener("scroll", updateTopbarOnScroll, { passive: true });
    scrollBound = true;
  }

  requireAuth(async (user) => {
    try {
      setDefaultUserUI(user);
      setPageVisible();
      await hydrateRole(user);
    } catch (error) {
      console.error("Home auth setup failed:", error);
      setDefaultUserUI(user);
      setPageVisible();
    }
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initHomePage, { once: true });
} else {
  initHomePage();
}
