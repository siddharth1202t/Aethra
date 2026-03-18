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
  let cssWidth = 0;
  let cssHeight = 0;
  let destroyed = false;

  function randomBetween(min, max) {
    return Math.random() * (max - min) + min;
  }

  function resizeCanvas() {
    if (destroyed) {
      return;
    }

    const dpr = window.devicePixelRatio || 1;
    const rect = targetCanvas.getBoundingClientRect();

    cssWidth = Math.max(1, rect.width || window.innerWidth || 1);
    cssHeight = Math.max(1, rect.height || window.innerHeight || 1);

    targetCanvas.width = Math.floor(cssWidth * dpr);
    targetCanvas.height = Math.floor(cssHeight * dpr);

    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
  }

  function buildStars() {
    if (destroyed) {
      return;
    }

    stars.length = 0;

    for (let i = 0; i < count; i += 1) {
      stars.push({
        x: randomBetween(0, cssWidth),
        y: randomBetween(0, cssHeight),
        radius: randomBetween(1, 3.2),
        alphaMin: randomBetween(0.18, 0.4),
        alphaMax: randomBetween(0.65, 1),
        speed: randomBetween(0.4, 1.2),
        phase: randomBetween(0, Math.PI * 2)
      });
    }
  }

  function draw(time) {
    if (destroyed) {
      return;
    }

    ctx.clearRect(0, 0, cssWidth, cssHeight);

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
    if (destroyed) {
      return;
    }

    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      resizeCanvas();
      buildStars();
    }, 120);
  }

  function destroy() {
    destroyed = true;

    if (animationFrameId !== null) {
      window.cancelAnimationFrame(animationFrameId);
      animationFrameId = null;
    }

    window.clearTimeout(resizeTimer);
    window.removeEventListener("resize", handleResize);
    window.removeEventListener("pagehide", destroy);
    window.removeEventListener("beforeunload", destroy);
  }

  function init() {
    resizeCanvas();
    buildStars();
    animationFrameId = window.requestAnimationFrame(draw);
  }

  window.addEventListener("resize", handleResize);
  window.addEventListener("pagehide", destroy);
  window.addEventListener("beforeunload", destroy);

  init();
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
