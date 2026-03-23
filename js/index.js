// ================================
// AETHRA FINAL ENGINE (CINEMATIC + EMOTIONAL)
// ================================

// ---------- ELEMENTS ----------
const body = document.body;
const nav = document.querySelector(".nav");
const heroCard = document.getElementById("heroCard");
const leftPanel = document.getElementById("leftPanel");
const rightPanel = document.getElementById("rightPanel");
const aurora = document.querySelector(".aurora");

const modal = document.getElementById("characterModal");
const modalCard = modal?.querySelector(".modal-card");
const closeModalBtn = document.getElementById("closeModal");

const modalImage = document.getElementById("modalImage");
const modalName = document.getElementById("modalName");
const modalRole = document.getElementById("modalRole");
const modalDesc = document.getElementById("modalDesc");
const modalTraits = document.getElementById("modalTraits");

const characterCards = [...document.querySelectorAll(".char-card")];

const revealTargets = [
  ...document.querySelectorAll(
    ".hero-card, .side-panel, .section-head, .char-card, .about-section"
  )
];

// ---------- HELPERS ----------
const clamp = (v, min, max) => Math.min(Math.max(v, min), max);
const reducedMotion = () =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---------- REVEAL ----------
function initReveal() {
  if (reducedMotion()) return;

  const obs = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      e.target.style.opacity = "1";
      e.target.style.transform = "translateY(0)";
      obs.unobserve(e.target);
    });
  });

  revealTargets.forEach((el, i) => {
    el.style.opacity = "0";
    el.style.transform = "translateY(30px)";
    el.style.transition =
      "all 0.9s cubic-bezier(0.22, 1, 0.36, 1)";
    el.style.transitionDelay = `${i * 40}ms`;
    obs.observe(el);
  });
}

// ---------- NAV ----------
function initNav() {
  const onScroll = () => {
    const scrolled = window.scrollY > 20;
    nav.classList.toggle("nav-scrolled", scrolled);
  };
  window.addEventListener("scroll", onScroll, { passive: true });
}

// ---------- TILT ----------
function attachTilt(el) {
  if (!el || reducedMotion()) return;

  el.addEventListener("pointermove", (e) => {
    const r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;

    el.style.transform = `
      perspective(900px)
      rotateX(${(-y * 8).toFixed(2)}deg)
      rotateY(${(x * 8).toFixed(2)}deg)
      scale(1.02)
    `;
  });

  el.addEventListener("pointerleave", () => {
    el.style.transform = "";
  });
}

// ---------- MODAL ----------
function openModal(card) {
  modal.classList.add("active");
  modal.setAttribute("aria-hidden", "false");

  modalImage.src = card.dataset.image;
  modalName.textContent = card.dataset.name;
  modalRole.textContent = card.dataset.role;
  modalDesc.textContent = card.dataset.desc;

  modalTraits.innerHTML = "";
  card.dataset.traits.split(",").forEach((t) => {
    const span = document.createElement("span");
    span.className = "trait";
    span.textContent = t.trim();
    modalTraits.appendChild(span);
  });
}

function closeModal() {
  modal.classList.remove("active");
  modal.setAttribute("aria-hidden", "true");
}

// ---------- PARALLAX ----------
function initParallax() {
  if (reducedMotion()) return;

  window.addEventListener("pointermove", (e) => {
    const x = (e.clientX / window.innerWidth - 0.5) * 10;
    const y = (e.clientY / window.innerHeight - 0.5) * 10;

    aurora.style.transform = `translate(${x}px, ${y}px)`;
  });
}

// ---------- CURSOR GLOW ----------
function initCursorGlow() {
  if (reducedMotion()) return;

  const glow = document.createElement("div");
  glow.className = "cursor-glow";
  document.body.appendChild(glow);

  window.addEventListener("pointermove", (e) => {
    glow.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
  });
}

// ---------- PRESENCE PULSE ----------
function initPresence() {
  if (reducedMotion()) return;

  document.querySelectorAll(".side-panel img").forEach((img) => {
    let t = 0;
    function loop() {
      t += 0.01;
      img.style.transform = `scale(${1 + Math.sin(t) * 0.01})`;
      requestAnimationFrame(loop);
    }
    loop();
  });
}

// ---------- EMOTIONAL AI ILLUSION ----------
function initEmotionalLayer() {
  const messages = [
    "You came back.",
    "They remember you.",
    "Something feels familiar.",
    "You’ve been here before.",
    "They noticed you were gone."
  ];

  const box = document.createElement("div");
  box.className = "presence-text";
  document.body.appendChild(box);

  function showMessage(text) {
    box.textContent = text;
    box.classList.add("visible");

    setTimeout(() => {
      box.classList.remove("visible");
    }, 3000);
  }

  // return illusion
  if (localStorage.getItem("aethra_return")) {
    setTimeout(() => showMessage("You came back."), 1500);
  }
  localStorage.setItem("aethra_return", "1");

  // idle detection
  let idleTimer;
  function resetIdle() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      const msg = messages[Math.floor(Math.random() * messages.length)];
      showMessage(msg);
    }, 15000);
  }

  ["mousemove", "keydown", "scroll"].forEach((e) =>
    window.addEventListener(e, resetIdle)
  );

  resetIdle();
}

// ---------- INIT ----------
function init() {
  initReveal();
  initNav();
  initParallax();
  initCursorGlow();
  initPresence();
  initEmotionalLayer();

  characterCards.forEach((c) => {
    attachTilt(c);
    c.addEventListener("click", () => openModal(c));
  });

  closeModalBtn?.addEventListener("click", closeModal);
}

document.readyState === "loading"
  ? document.addEventListener("DOMContentLoaded", init)
  : init();
