const canvas = document.getElementById("starsCanvas");

function createStarField(targetCanvas, count = 90) {
  if (!targetCanvas) {
    return;
  }

  const ctx = targetCanvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const stars = [];
  let animationFrameId = null;
  let resizeTimer = null;

  function randomBetween(min, max) {
    return Math.random() * (max - min) + min;
  }

  function resizeCanvas() {
    const dpr = window.devicePixelRatio || 1;
    const rect = targetCanvas.getBoundingClientRect();

    targetCanvas.width = Math.max(1, Math.floor(rect.width * dpr));
    targetCanvas.height = Math.max(1, Math.floor(rect.height * dpr));

    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
  }

  function buildStars() {
    stars.length = 0;

    const rect = targetCanvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;

    for (let i = 0; i < count; i += 1) {
      stars.push({
        x: randomBetween(0, width),
        y: randomBetween(0, height),
        radius: randomBetween(1, 3.2),
        alphaMin: randomBetween(0.18, 0.4),
        alphaMax: randomBetween(0.65, 1),
        speed: randomBetween(0.4, 1.2),
        phase: randomBetween(0, Math.PI * 2)
      });
    }
  }

  function draw(time) {
    const rect = targetCanvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;

    ctx.clearRect(0, 0, width, height);

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
    animationFrameId = window.requestAnimationFrame(draw);
  }

  function handleResize() {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      resizeCanvas();
      buildStars();
    }, 120);
  }

  function init() {
    resizeCanvas();
    buildStars();
    animationFrameId = window.requestAnimationFrame(draw);
  }

  window.addEventListener("resize", handleResize);
  init();

  window.addEventListener("beforeunload", () => {
    if (animationFrameId !== null) {
      window.cancelAnimationFrame(animationFrameId);
    }
    window.clearTimeout(resizeTimer);
  });
}

if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    () => createStarField(canvas),
    { once: true }
  );
} else {
  createStarField(canvas);
}
