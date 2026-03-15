let pageLoadTime = Date.now();
let interactionCount = 0;

document.addEventListener("mousemove", () => interactionCount++);
document.addEventListener("keydown", () => interactionCount++);
document.addEventListener("click", () => interactionCount++);

export function detectBotBehavior() {

  const timeOnPage = Date.now() - pageLoadTime;

  if (timeOnPage < 1500) {
    return {
      suspicious: true,
      reason: "Login attempted too quickly after page load"
    };
  }

  if (interactionCount < 2) {
    return {
      suspicious: true,
      reason: "Very low human interaction detected"
    };
  }

  return { suspicious: false };
}
