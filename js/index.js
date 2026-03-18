const modal = document.getElementById("characterModal");
const modalImage = document.getElementById("modalImage");
const modalName = document.getElementById("modalName");
const modalRole = document.getElementById("modalRole");
const modalDesc = document.getElementById("modalDesc");
const modalTraits = document.getElementById("modalTraits");
const closeModalBtn = document.getElementById("closeModal");

function openModal(card) {
  if (!modal || !modalImage || !modalName || !modalRole || !modalDesc || !modalTraits) {
    return;
  }

  modalImage.src = card.dataset.image || "";
  modalImage.alt = card.dataset.name || "Character";
  modalName.textContent = card.dataset.name || "";
  modalRole.textContent = card.dataset.role || "";
  modalDesc.textContent = card.dataset.desc || "";
  modalTraits.replaceChildren();

  const traits = String(card.dataset.traits || "")
    .split(",")
    .map((trait) => trait.trim())
    .filter(Boolean);

  for (const trait of traits) {
    const span = document.createElement("span");
    span.className = "trait";
    span.textContent = trait;
    modalTraits.appendChild(span);
  }

  modal.classList.add("active");
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
}

function closeCharacterModal() {
  if (!modal) {
    return;
  }

  modal.classList.remove("active");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}

function bindCharacterCards() {
  const cards = document.querySelectorAll(".char-card");

  for (const card of cards) {
    card.addEventListener("click", () => openModal(card));

    card.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openModal(card);
      }
    });
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
    if (event.key === "Escape" && modal?.classList.contains("active")) {
      closeCharacterModal();
    }
  });
}

function initIndexPage() {
  bindCharacterCards();
  bindModalEvents();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initIndexPage, { once: true });
} else {
  initIndexPage();
}
