const starsContainer = document.getElementById("stars");
const particlesContainer = document.getElementById("particles");
const petalsContainer = document.getElementById("petals");
const modal = document.getElementById("characterModal");
const modalImage = document.getElementById("modalImage");
const modalName = document.getElementById("modalName");
const modalRole = document.getElementById("modalRole");
const modalDesc = document.getElementById("modalDesc");
const modalTraits = document.getElementById("modalTraits");
const closeModalBtn = document.getElementById("closeModal");
const leftPanel = document.getElementById("leftPanel");
const rightPanel = document.getElementById("rightPanel");
const heroCard = document.getElementById("heroCard");

let mouseX = 0;
let mouseY = 0;
let currentX = 0;
let currentY = 0;

function createStars() {
  if (!starsContainer) return;

  for (let i = 0; i < 110; i += 1) {
    const star = document.createElement("div");
    star.classList.add("star");

    const size = Math.random() * 2.2 + 1;
    star.style.width = `${size}px`;
    star.style.height = `${size}px`;
    star.style.left = `${Math.random() * 100}vw`;
    star.style.top = `${Math.random() * 100}vh`;
    star.style.animationDuration = `${Math.random() * 4 + 2}s`;
    star.style.animationDelay = `${Math.random() * 4}s`;

    starsContainer.appendChild(star);
  }
}

function createParticles() {
  if (!particlesContainer) return;

  for (let i = 0; i < 24; i += 1) {
    const particle = document.createElement("div");
    particle.classList.add("particle");

    const size = Math.random() * 5 + 3;
    particle.style.width = `${size}px`;
    particle.style.height = `${size}px`;
    particle.style.left = `${Math.random() * 100}vw`;
    particle.style.bottom = `${-Math.random() * 100}px`;
    particle.style.animationDuration = `${Math.random() * 10 + 8}s`;
    particle.style.animationDelay = `${Math.random() * 8}s`;

    particlesContainer.appendChild(particle);
  }
}

function createPetals() {
  if (!petalsContainer) return;

  for (let i = 0; i < 22; i += 1) {
    const petal = document.createElement("div");
    petal.classList.add("petal");

    petal.style.left = `${Math.random() * 100}vw`;
    petal.style.top = `${-Math.random() * 100}px`;
    petal.style.animationDuration = `${Math.random() * 8 + 9}s`;
    petal.style.animationDelay = `${Math.random() * 10}s`;
    petal.style.transform = `rotate(${Math.random() * 360}deg)`;

    petalsContainer.appendChild(petal);
  }
}

function openModal(card) {
  if (!modal || !modalImage || !modalName || !modalRole || !modalDesc || !modalTraits) {
    return;
  }

  modalImage.src = card.dataset.image || "";
  modalImage.alt = card.dataset.name || "Character";
  modalName.textContent = card.dataset.name || "";
  modalRole.textContent = card.dataset.role || "";
  modalDesc.textContent = card.dataset.desc || "";
  modalTraits.textContent = "";

  const traits = String(card.dataset.traits || "")
    .split(",")
    .map((trait) => trait.trim())
    .filter(Boolean);

  traits.forEach((trait) => {
    const span = document.createElement("span");
    span.className = "trait";
    span.textContent = trait;
    modalTraits.appendChild(span);
  });

  modal.classList.add("active");
  modal.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
}

function closeCharacterModal() {
  if (!modal) return;

  modal.classList.remove("active");
  modal.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
}

function bindCharacterCards() {
  const cards = document.querySelectorAll(".char-card");

  cards.forEach((card) => {
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

function bindParallax() {
  document.addEventListener("mousemove", (event) => {
    mouseX = (window.innerWidth / 2 - event.clientX) / 35;
    mouseY = (window.innerHeight / 2 - event.clientY) / 35;
  });

  function animateParallax() {
    currentX += (mouseX - currentX) * 0.08;
    currentY += (mouseY - currentY) * 0.08;

    if (leftPanel) {
      leftPanel.style.transform = `translate(${currentX * 0.8}px, ${currentY * 0.8}px)`;
    }

    if (rightPanel) {
      rightPanel.style.transform = `translate(${-currentX * 0.8}px, ${-currentY * 0.8}px)`;
    }

    window.requestAnimationFrame(animateParallax);
  }

  animateParallax();

  heroCard?.addEventListener("mousemove", (event) => {
    const rect = heroCard.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    heroCard.style.setProperty("--mx", `${x}px`);
    heroCard.style.setProperty("--my", `${y}px`);
  });

  heroCard?.addEventListener("mouseleave", () => {
    heroCard.style.setProperty("--mx", "50%");
    heroCard.style.setProperty("--my", "50%");
  });
}

function initIndexPage() {
  createStars();
  createParticles();
  createPetals();
  bindCharacterCards();
  bindModalEvents();
  bindParallax();
}

initIndexPage();
