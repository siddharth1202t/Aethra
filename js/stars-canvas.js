const canvas = document.getElementById("starsCanvas");

function createAmbientScene(targetCanvas) {
  if (!targetCanvas) {
    return;
  }

  const ctx = targetCanvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const scene = targetCanvas.dataset.scene || "auth";
  const isHomeScene = scene === "home";

  const stars = [];
  const petals = [];
  const particles = [];

  let animationFrameId = null;
  let resizeTimer = null;
  let cssWidth = 0;
  let cssHeight = 0;
  let lastTime = performance.now();

  const starCount = isHomeScene ? 120 : 90;
  const petalCount = isHomeScene ? 18 : 0;
  const particleCount = isHomeScene ? 14 : 0;

  function randomBetween(min, max) {
    return Math.random() * (max - min) + min;
  }

  function resizeCanvas() {
    const dpr = window.devicePixelRatio || 1;
    cssWidth = Math.max(1, window.innerWidth);
    cssHeight = Math.max(1, window.innerHeight);

    targetCanvas.width = Math.floor(cssWidth * dpr);
    targetCanvas.height = Math.floor(cssHeight * dpr);

    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
  }

  function buildStars() {
    stars.length = 0;

    for (let i = 0; i < starCount; i += 1) {
      stars.push({
        x: randomBetween(0, cssWidth),
        y: randomBetween(0, cssHeight),
        radius: randomBetween(1, 3),
        alphaMin: randomBetween(0.15, 0.35),
        alphaMax: randomBetween(0.65, 1),
        speed: randomBetween(0.35, 1.1),
        phase: randomBetween(0, Math.PI * 2)
      });
    }
  }

  function buildPetals() {
    petals.length = 0;

    for (let i = 0; i < petalCount; i += 1) {
      petals.push({
        x: randomBetween(0, cssWidth),
        y: randomBetween(-cssHeight, cssHeight),
        width: randomBetween(10, 16),
        height: randomBetween(6, 10),
        speedY: randomBetween(18, 34),
        speedX: randomBetween(6, 16),
        rotation: randomBetween(0, Math.PI * 2),
        rotationSpeed: randomBetween(0.3, 1.1),
        swayPhase: randomBetween(0, Math.PI * 2)
      });
    }
  }

  function buildParticles() {
    particles.length = 0;

    for (let i = 0; i < particleCount; i += 1) {
      particles.push({
        x: randomBetween(0, cssWidth),
        y: randomBetween(0, cssHeight),
        radius: randomBetween(2, 4.5),
        speedY: randomBetween(12, 28),
        alpha: randomBetween(0.18, 0.4),
        drift: randomBetween(-10, 10),
        phase: randomBetween(0, Math.PI * 2)
      });
    }
  }

  function resetPetal(petal) {
    petal.x = randomBetween(0, cssWidth);
    petal.y = randomBetween(-120, -20);
    petal.width = randomBetween(10, 16);
    petal.height = randomBetween(6, 10);
    petal.speedY = randomBetween(18, 34);
    petal.speedX = randomBetween(6, 16);
    petal.rotation = randomBetween(0, Math.PI * 2);
    petal.rotationSpeed = randomBetween(0.3, 1.1);
    petal.swayPhase = randomBetween(0, Math.PI * 2);
  }

  function resetParticle(particle) {
    particle.x = randomBetween(0, cssWidth);
    particle.y = randomBetween(cssHeight + 20, cssHeight + 180);
    particle.radius = randomBetween(2, 4.5);
    particle.speedY = randomBetween(12, 28);
    particle.alpha = randomBetween(0.18, 0.4);
    particle.drift = randomBetween(-10, 10);
    particle.phase = randomBetween(0, Math.PI * 2);
  }

  function drawStars(time) {
    for (const star of stars) {
      const alphaRange = star.alphaMax - star.alphaMin;
      const alpha =
        star.alphaMin +
        ((Math.sin(time * 0.001 * star.speed + star.phase) + 1) / 2) * alphaRange;

      ctx.beginPath();
      ctx.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(255, 255, 255, ${alpha})`;
      ctx.shadowBlur = 8;
      ctx.shadowColor = `rgba(255, 255, 255, ${Math.min(alpha, 0.9)})`;
      ctx.fill();
    }

    ctx.shadowBlur = 0;
  }

  function drawPetals(deltaSeconds, time) {
    for (const petal of petals) {
      petal.y += petal.speedY * deltaSeconds;
      petal.x += Math.sin(time * 0.0015 + petal.swayPhase) * 0.35 + petal.speedX * 0.02;
      petal.rotation += petal.rotationSpeed * deltaSeconds;

      if (petal.y > cssHeight + 40 || petal.x > cssWidth + 60) {
        resetPetal(petal);
      }

      ctx.save();
      ctx.translate(petal.x, petal.y);
      ctx.rotate(petal.rotation);
      ctx.beginPath();
      ctx.ellipse(0, 0, petal.width / 2, petal.height / 2, 0, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(255, 214, 236, 0.85)";
      ctx.shadowBlur = 6;
      ctx.shadowColor = "rgba(255, 194, 223, 0.28)";
      ctx.fill();
      ctx.restore();
    }

    ctx.shadowBlur = 0;
  }

  function drawParticles(deltaSeconds, time) {
    for (const particle of particles) {
      particle.y -= particle.speedY * deltaSeconds;
      particle.x += Math.sin(time * 0.001 + particle.phase) * 0.15 + particle.drift * 0.01;

      if (particle.y < -30) {
        resetParticle(particle);
      }

      ctx.beginPath();
      ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(155, 214, 255, ${particle.alpha})`;
      ctx.shadowBlur = 12;
      ctx.shadowColor = `rgba(155, 214, 255, ${Math.min(particle.alpha + 0.15, 0.8)})`;
      ctx.fill();
    }

    ctx.shadowBlur = 0;
  }

  function draw(time) {
    const deltaSeconds = Math.min((time - lastTime) / 1000, 0.05);
    lastTime = time;

    ctx.clearRect(0, 0, cssWidth, cssHeight);
    drawStars(time);

    if (isHomeScene) {
      drawParticles(deltaSeconds, time);
      drawPetals(deltaSeconds, time);
    }

    animationFrameId = window.requestAnimationFrame(draw);
  }

  function rebuildScene() {
    resizeCanvas();
    buildStars();
    buildPetals();
    buildParticles();
  }

  function handleResize() {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      rebuildScene();
    }, 120);
  }

  function init() {
    rebuildScene();
    animationFrameId = window.requestAnimationFrame(draw);
  }

  window.addEventListener("resize", handleResize);

  window.addEventListener("beforeunload", () => {
    if (animationFrameId !== null) {
      window.cancelAnimationFrame(animationFrameId);
    }
    window.clearTimeout(resizeTimer);
  });

  init();
}

if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    () => createAmbientScene(canvas),
    { once: true }
  );
} else {
  createAmbientScene(canvas);
}
