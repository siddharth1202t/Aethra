const starsContainer = document.getElementById("stars");

function createStars(count = 90) {
  if (!starsContainer) return;

  const fragment = document.createDocumentFragment();

  for (let i = 0; i < count; i += 1) {
    const star = document.createElement("div");
    star.className = "star";

    const size = Math.random() * 2.2 + 1;
    star.style.width = `${size}px`;
    star.style.height = `${size}px`;
    star.style.left = `${Math.random() * 100}vw`;
    star.style.top = `${Math.random() * 100}vh`;
    star.style.animationDuration = `${Math.random() * 4 + 2}s`;
    star.style.animationDelay = `${Math.random() * 4}s`;

    fragment.appendChild(star);
  }

  starsContainer.appendChild(fragment);
}

createStars();
