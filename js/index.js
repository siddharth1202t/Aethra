const modal = document.getElementById("characterModal");
const modalImage = document.getElementById("modalImage");
const modalName = document.getElementById("modalName");
const modalRole = document.getElementById("modalRole");
const modalDesc = document.getElementById("modalDesc");
const modalTraits = document.getElementById("modalTraits");
const closeModalBtn = document.getElementById("closeModal");

let lastTriggerElement = null;
let pageInitialized = false;

function isModalOpen() {
  return Boolean(modal?.classList.contains("active"));
}

function getFocusableElements(container) {
  if (!container) {
    return [];
  }

  return Array.from(
    container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
  ).filter((element) => !element.hasAttribute("disabled"));
}

function buildTraits(traitsValue = "") {
  const traits = String(traitsValue)
    .split(",")
    .map((trait) => trait.trim())
    .filter(Boolean);

  modalTraits?.replaceChildren();

  for (const trait of traits) {
    const span = document.createElement("span");
    span.className = "trait";
    span.textContent = trait;
    modalTraits?.appendChild(span);
  }
}

function populateModal(card) {
  if (!card || !modalImage || !modalName || !modalRole || !modalDesc || !modalTraits) {
    return;
  }

  const imageSrc = card.dataset.image || "";
  const imageAlt = card.dataset.name || "Character";

  modalImage.src = imageSrc;
  modalImage.alt = imageAlt;
  modalName.textContent = card.dataset.name || "";
  modalRole.textContent = card.dataset.role || "";
  modalDesc.textContent = card.dataset.desc || "";

  buildTraits(card.dataset.traits || "");
}

function openModal(card) {
  if (!modal || !card) {
    return;
  }

  lastTriggerElement = card;
  populateModal(card);

  modal.classList.add("active");
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");

  window.setTimeout(() => {
    closeModalBtn?.focus();
  }, 20);
}

function closeCharacterModal() {
  if (!modal) {
    return;
  }

  modal.classList.remove("active");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");

  if (lastTriggerElement && typeof lastTriggerElement.focus === "function") {
    window.setTimeout(() => {
      lastTriggerElement.focus();
    }, 20);
  }
}

function handleCardKeydown(event, card) {
  if (!card) {
    return;
  }

  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    openModal(card);
  }
}

function bindCharacterCards() {
  const cards = document.querySelectorAll(".char-card");

  for (const card of cards) {
    const imageSrc = card.dataset.image || "";
    if (imageSrc) {
      const preloader = new Image();
      preloader.src = imageSrc;
    }

    card.addEventListener("click", () => openModal(card));
    card.addEventListener("keydown", (event) => handleCardKeydown(event, card));
  }
}

function trapModalFocus(event) {
  if (!isModalOpen() || !modal) {
    return;
  }

  if (event.key !== "Tab") {
    return;
  }

  const focusable = getFocusableElements(modal);
  if (!focusable.length) {
    event.preventDefault();
    return;
  }

  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const active = document.activeElement;

  if (event.shiftKey && active === first) {
    event.preventDefault();
    last.focus();
    return;
  }

  if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

function bindModalEvents() {
  closeModalBtn?.addEventListener("click", closeCharacterModal);

  modal?.addEventListener("click", (event) => {
    if (event.target === modal) {
      closeCharacterModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isModalOpen()) {
      closeCharacterModal();
      return;
    }

    trapModalFocus(event);
  });
}

function initIndexPage() {
  if (pageInitialized) {
    return;
  }

  bindCharacterCards();
  bindModalEvents();
  pageInitialized = true;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initIndexPage, { once: true });
} else {
  initIndexPage();
}
