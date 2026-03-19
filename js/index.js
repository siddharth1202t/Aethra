const body = document.body;
const nav = document.querySelector(".nav");
const heroCard = document.getElementById("heroCard");
const leftPanel = document.getElementById("leftPanel");
const rightPanel = document.getElementById("rightPanel");

const modal = document.getElementById("characterModal");
const modalCard = modal?.querySelector(".modal-card");
const closeModalBtn = document.getElementById("closeModal");
const modalImage = document.getElementById("modalImage");
const modalName = document.getElementById("modalName");
const modalRole = document.getElementById("modalRole");
const modalDesc = document.getElementById("modalDesc");
const modalTraits = document.getElementById("modalTraits");

const characterCards = Array.from(document.querySelectorAll(".char-card"));
const revealTargets = Array.from(
  document.querySelectorAll(
    ".hero-card, .side-panel, .section-head, .char-card, .about-section"
  )
);

let activeModalTrigger = null;
let rafId = 0;

/* ---------------- BASIC HELPERS ---------------- */

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function setStyles(element, styles = {}) {
  if (!element) return;
  Object.assign(element.style, styles);
}

/* ---------------- PAGE REVEAL ---------------- */

function initPageReveal() {
  revealTargets.forEach((element, index) => {
    if (!element) return;
    element.style.opacity = "0";
    element.style.transform = "translateY(26px)";
    element.style.transition =
      "opacity 0.7s ease, transform 0.7s cubic-bezier(0.22, 1, 0.36, 1)";
    element.style.transitionDelay = `${Math.min(index * 40, 220)}ms`;
  });

  const reveal = () => {
    revealTargets.forEach((element) => {
      if (!element) return;
      element.style.opacity = "1";
      element.style.transform = "translateY(0)";
    });
  };

  if (prefersReducedMotion()) {
    reveal();
    return;
  }

  window.requestAnimationFrame(() => {
    window.requestAnimationFrame(reveal);
  });
}

/* ---------------- NAV SCROLL POLISH ---------------- */

function updateNavOnScroll() {
  if (!nav) return;

  const scrolled = window.scrollY > 24;
  nav.classList.toggle("nav-scrolled", scrolled);

  if (scrolled) {
    setStyles(nav, {
      background:
        "linear-gradient(180deg, rgba(18, 8, 40, 0.82), rgba(18, 8, 40, 0.6))",
      boxShadow:
        "0 18px 48px rgba(0, 0, 0, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.05)",
      borderColor: "rgba(255, 255, 255, 0.14)"
    });
  } else {
    setStyles(nav, {
      background:
        "linear-gradient(180deg, rgba(18, 8, 40, 0.68), rgba(18, 8, 40, 0.46))",
      boxShadow:
        "0 16px 44px rgba(0, 0, 0, 0.24), inset 0 1px 0 rgba(255, 255, 255, 0.05)",
      borderColor: "rgba(255, 255, 255, 0.12)"
    });
  }
}

/* ---------------- PREMIUM POINTER TILT ---------------- */

function attachTilt(element, options = {}) {
  if (!element || prefersReducedMotion()) return;

  const {
    maxRotate = 8,
    scale = 1.01,
    perspective = 900
  } = options;

  let rect = null;

  function onMove(event) {
    rect = rect || element.getBoundingClientRect();

    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    const px = x / rect.width;
    const py = y / rect.height;

    const rotateY = (px - 0.5) * maxRotate * 2;
    const rotateX = (0.5 - py) * maxRotate * 2;

    element.style.transform = `
      perspective(${perspective}px)
      rotateX(${rotateX.toFixed(2)}deg)
      rotateY(${rotateY.toFixed(2)}deg)
      scale(${scale})
    `;
  }

  function onEnter() {
    rect = element.getBoundingClientRect();
    element.style.willChange = "transform";
    element.style.transition =
      "transform 0.18s ease, box-shadow 0.28s ease, border-color 0.28s ease";
  }

  function onLeave() {
    rect = null;
    element.style.transition =
      "transform 0.35s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.28s ease, border-color 0.28s ease";
    element.style.transform = "";
    window.setTimeout(() => {
      element.style.willChange = "auto";
    }, 350);
  }

  element.addEventListener("pointerenter", onEnter);
  element.addEventListener("pointermove", onMove);
  element.addEventListener("pointerleave", onLeave);
}

function initPremiumMotion() {
  attachTilt(heroCard, { maxRotate: 5, scale: 1.008, perspective: 1100 });
  attachTilt(leftPanel, { maxRotate: 4, scale: 1.01, perspective: 950 });
  attachTilt(rightPanel, { maxRotate: 4, scale: 1.01, perspective: 950 });

  characterCards.forEach((card) => {
    attachTilt(card, { maxRotate: 7, scale: 1.015, perspective: 950 });
  });
}

/* ---------------- SCROLL REVEAL ---------------- */

function initScrollReveal() {
  if (prefersReducedMotion()) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        const el = entry.target;

        if (entry.isIntersecting) {
          el.style.opacity = "1";
          el.style.transform = "translateY(0)";
          observer.unobserve(el);
        }
      });
    },
    {
      threshold: 0.14,
      rootMargin: "0px 0px -40px 0px"
    }
  );

  revealTargets.forEach((el) => {
    if (!el) return;
    observer.observe(el);
  });
}

/* ---------------- CHARACTER MODAL ---------------- */

function buildTraitChip(text) {
  const chip = document.createElement("span");
  chip.className = "trait";
  chip.textContent = text;
  return chip;
}

function fillModalFromCard(card) {
  if (!card || !modalImage || !modalName || !modalRole || !modalDesc || !modalTraits) {
    return;
  }

  const name = card.dataset.name || "";
  const role = card.dataset.role || "";
  const image = card.dataset.image || "";
  const desc = card.dataset.desc || "";
  const traits = String(card.dataset.traits || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  modalImage.src = image;
  modalImage.alt = name ? `${name} character artwork` : "Character artwork";
  modalName.textContent = name;
  modalRole.textContent = role;
  modalDesc.textContent = desc;

  modalTraits.replaceChildren(...traits.map(buildTraitChip));
}

function openModal(card) {
  if (!modal || !modalCard || !card) return;

  activeModalTrigger = card;
  fillModalFromCard(card);

  modal.classList.add("active");
  modal.setAttribute("aria-hidden", "false");
  body.classList.add("modal-open");

  if (!prefersReducedMotion()) {
    modal.style.opacity = "0";
    modalCard.style.transform = "translateY(20px) scale(0.98)";
    modalCard.style.opacity = "0";

    window.requestAnimationFrame(() => {
      modal.style.transition = "opacity 0.25s ease";
      modalCard.style.transition =
        "transform 0.3s cubic-bezier(0.22, 1, 0.36, 1), opacity 0.25s ease";
      modal.style.opacity = "1";
      modalCard.style.transform = "translateY(0) scale(1)";
      modalCard.style.opacity = "1";
    });
  }

  window.setTimeout(() => {
    closeModalBtn?.focus();
  }, 30);
}

function closeModal() {
  if (!modal || !modal.classList.contains("active")) return;

  const finishClose = () => {
    modal.classList.remove("active");
    modal.setAttribute("aria-hidden", "true");
    body.classList.remove("modal-open");

    modal.style.opacity = "";
    modal.style.transition = "";
    if (modalCard) {
      modalCard.style.transform = "";
      modalCard.style.opacity = "";
      modalCard.style.transition = "";
    }

    activeModalTrigger?.focus?.();
    activeModalTrigger = null;
  };

  if (prefersReducedMotion()) {
    finishClose();
    return;
  }

  modal.style.opacity = "0";
  if (modalCard) {
    modalCard.style.transform = "translateY(16px) scale(0.985)";
    modalCard.style.opacity = "0";
  }

  window.setTimeout(finishClose, 220);
}

function bindCharacterCards() {
  characterCards.forEach((card) => {
    card.addEventListener("click", () => openModal(card));

    card.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openModal(card);
      }
    });
  });
}

function bindModalEvents() {
  closeModalBtn?.addEventListener("click", closeModal);

  modal?.addEventListener("click", (event) => {
    if (event.target === modal) {
      closeModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && modal?.classList.contains("active")) {
      closeModal();
    }
  });
}

/* ---------------- PARALLAX POLISH ---------------- */

function initHeroParallax() {
  if (prefersReducedMotion()) return;

  const aurora = document.querySelector(".aurora");
  if (!aurora) return;

  function onMove(event) {
    if (rafId) cancelAnimationFrame(rafId);

    rafId = requestAnimationFrame(() => {
      const x = (event.clientX / window.innerWidth - 0.5) * 12;
      const y = (event.clientY / window.innerHeight - 0.5) * 12;

      aurora.style.transform = `translate3d(${x}px, ${y}px, 0)`;
    });
  }

  window.addEventListener("pointermove", onMove, { passive: true });
}

/* ---------------- INIT ---------------- */

function init() {
  initPageReveal();
  initScrollReveal();
  updateNavOnScroll();
  initPremiumMotion();
  bindCharacterCards();
  bindModalEvents();
  initHeroParallax();

  window.addEventListener("scroll", updateNavOnScroll, { passive: true });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
  init();
}
