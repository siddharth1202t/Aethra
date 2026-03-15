const starsContainer = document.getElementById("stars");

function createStars() {
  if (!starsContainer) return;

  for (let i = 0; i < 90; i += 1) {
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

createStars();
