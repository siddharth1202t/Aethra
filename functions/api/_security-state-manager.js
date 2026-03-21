import { getFirestore, FieldValue } from "firebase-admin/firestore";

const MAX_ID_LENGTH = 128;
const MAX_TYPE_LENGTH = 60;
const MAX_ROUTE_GROUP_LENGTH = 80;
const MAX_SOURCE_LENGTH = 50;
const MAX_LEVEL_LENGTH = 20;

function safeString(value, maxLength = 300) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeInt(value, fallback = 0, min = 0, max = 1_000_000) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function normalizeId(value = "", maxLength = MAX_ID_LENGTH) {
  return safeString(value || "", maxLength).replace(/[^a-zA-Z0-9._:@/-]/g, "");
}

function normalizeHash(value = "", maxLength = 64) {
  return safeString(value || "", maxLength)
    .toLowerCase()
    .replace(/[^a-f0-9]/g, "")
    .slice(0, maxLength);
}

function normalizeLevel(value = "") {
  const level = safeString(value || "warning", MAX_LEVEL_LENGTH).toLowerCase();
  if (["info", "warning", "error", "critical"].includes(level)) {
    return level;
  }
  return "warning";
}

function normalizeType(value = "") {
  return safeString(value || "unknown", MAX_TYPE_LENGTH).toLowerCase();
}

function normalizeRouteGroup(value = "") {
  return safeString(value || "unknown", MAX_ROUTE_GROUP_LENGTH).toLowerCase();
}

function normalizeSource(value = "") {
  return safeString(value || "unspecified", MAX_SOURCE_LENGTH).toLowerCase();
}

function getSeverityWeight(level = "") {
  const normalized = normalizeLevel(level);

  if (normalized === "critical") return 10;
  if (normalized === "error") return 6;
  if (normalized === "warning") return 3;
  return 1;
}

function getRiskDeltaByType(type = "", level = "") {
  const normalizedType = normalizeType(type);
  const severityWeight = getSeverityWeight(level);

  if (
    normalizedType.includes("login_failed") ||
    normalizedType.includes("signup_failed") ||
    normalizedType.includes("turnstile_verification_failed") ||
    normalizedType.includes("password_reset_failed")
  ) {
    return 3 * severityWeight;
  }

  if (
    normalizedType.includes("lockout") ||
    normalizedType.includes("blocked") ||
    normalizedType.includes("forbidden") ||
    normalizedType.includes("rate_limited")
  ) {
    return 5 * severityWeight;
  }

  if (
    normalizedType.includes("suspicious") ||
    normalizedType.includes("challenge") ||
    normalizedType.includes("throttle")
  ) {
    return 4 * severityWeight;
  }

  if (
    normalizedType.includes("success") ||
    normalizedType.includes("verified")
  ) {
    return -2;
  }

  return severityWeight;
}

function clampRiskScore(score) {
  return Math.min(100, Math.max(0, safeInt(score, 0, 0, 100)));
}

function getRiskLevel(score = 0) {
  const normalized = clampRiskScore(score);

  if (normalized >= 80) return "critical";
  if (normalized >= 55) return "high";
  if (normalized >= 25) return "medium";
  return "low";
}

function shouldIncrementCounter(type = "", matchers = []) {
  const normalizedType = normalizeType(type);
  return matchers.some((matcher) => normalizedType.includes(matcher));
}

function buildEntityDocPath(kind, id) {
  return `securityState/${kind}_${id}`;
}

function buildBasePatch(event = {}) {
  const nowMs = Date.now();
  const level = normalizeLevel(event.level);
  const type = normalizeType(event.type);
  const routeGroup = normalizeRouteGroup(event.routeGroup || "unknown");
  const source = normalizeSource(event.source);
  const severityWeight = getSeverityWeight(level);
  const riskDelta = getRiskDeltaByType(type, level);

  return {
    kind: safeString(event.kind || "unknown", 30),
    refId: safeString(event.refId || "", MAX_ID_LENGTH),
    lastEventType: type,
    lastLevel: level,
    lastSource: source,
    lastRouteGroup: routeGroup,
    lastSeenAtMs: nowMs,
    lastSeenAt: FieldValue.serverTimestamp(),
    totalEvents: FieldValue.increment(1),
    totalSeverityWeight: FieldValue.increment(severityWeight),
    rollingRiskScoreDelta: FieldValue.increment(riskDelta)
  };
}

function buildCounterPatch(event = {}) {
  const type = normalizeType(event.type);
  const level = normalizeLevel(event.level);

  const patch = {};

  if (level === "critical") {
    patch.criticalEvents = FieldValue.increment(1);
  } else if (level === "error") {
    patch.errorEvents = FieldValue.increment(1);
  } else if (level === "warning") {
    patch.warningEvents = FieldValue.increment(1);
  } else {
    patch.infoEvents = FieldValue.increment(1);
  }

  if (shouldIncrementCounter(type, ["login_failed"])) {
    patch.failedLoginCount = FieldValue.increment(1);
  }

  if (shouldIncrementCounter(type, ["signup_failed"])) {
    patch.failedSignupCount = FieldValue.increment(1);
  }

  if (shouldIncrementCounter(type, ["password_reset_failed"])) {
    patch.failedPasswordResetCount = FieldValue.increment(1);
  }

  if (shouldIncrementCounter(type, ["password_reset_requested"])) {
    patch.passwordResetRequestCount = FieldValue.increment(1);
  }

  if (
    shouldIncrementCounter(type, [
      "turnstile_verification_failed",
      "captcha_missing",
      "captcha_failed"
    ])
  ) {
    patch.captchaFailureCount = FieldValue.increment(1);
  }

  if (
    shouldIncrementCounter(type, [
      "blocked",
      "forbidden",
      "challenge",
      "throttle",
      "suspicious"
    ])
  ) {
    patch.suspiciousEventCount = FieldValue.increment(1);
  }

  if (shouldIncrementCounter(type, ["rate_limited"])) {
    patch.rateLimitHitCount = FieldValue.increment(1);
  }

  if (shouldIncrementCounter(type, ["lockout", "ip_login_lock"])) {
    patch.lockoutCount = FieldValue.increment(1);
  }

  if (
    shouldIncrementCounter(type, [
      "login_success",
      "signup_success",
      "google_login_success"
    ])
  ) {
    patch.successfulAuthCount = FieldValue.increment(1);
  }

  return patch;
}

async function readExistingState(db, docPath) {
  try {
    const snap = await db.doc(docPath).get();
    return snap.exists ? snap.data() || {} : {};
  } catch (error) {
    console.error("Failed to read security state:", error);
    return {};
  }
}

function buildRiskPatch(existing = {}, event = {}) {
  const currentRolling = safeInt(existing.rollingRiskScoreDelta, 0, 0, 100000);
  const delta = getRiskDeltaByType(event.type, event.level);
  const nextRolling = Math.max(0, currentRolling + delta);

  const normalizedRiskScore = clampRiskScore(
    Math.min(100, Math.floor(nextRolling / 3))
  );

  return {
    currentRiskScore: normalizedRiskScore,
    currentRiskLevel: getRiskLevel(normalizedRiskScore),
    lastRiskDelta: delta
  };
}

function buildStatePatch(existing = {}, event = {}) {
  return {
    ...buildBasePatch(event),
    ...buildCounterPatch(event),
    ...buildRiskPatch(existing, event)
  };
}

async function updateEntityState(db, kind, refId, event) {
  if (!refId) {
    return false;
  }

  const docPath = buildEntityDocPath(kind, refId);
  const existing = await readExistingState(db, docPath);

  const patch = buildStatePatch(existing, {
    ...event,
    kind,
    refId
  });

  try {
    await db.doc(docPath).set(patch, { merge: true });
    return true;
  } catch (error) {
    console.error(`Failed to update security state for ${kind}:`, error);
    return false;
  }
}

function getEntityTargets(event = {}) {
  const targets = [];

  const userId = normalizeId(event.userId || "");
  const emailHash = normalizeHash(event.emailHash || "");
  const ipHash = normalizeHash(event.ipHash || "");
  const sessionId = normalizeId(event.sessionId || "");

  if (userId) {
    targets.push({ kind: "user", refId: userId });
  }

  if (emailHash) {
    targets.push({ kind: "email", refId: emailHash });
  }

  if (ipHash) {
    targets.push({ kind: "ip", refId: ipHash });
  }

  if (sessionId) {
    targets.push({ kind: "session", refId: sessionId });
  }

  return targets;
}

export async function updateSecurityState(dbOrEvent, maybeEvent = null) {
  const db =
    maybeEvent === null ? getFirestore() : dbOrEvent;

  const event =
    maybeEvent === null ? dbOrEvent : maybeEvent;

  if (!db || !event || typeof event !== "object") {
    return { ok: false, updated: 0 };
  }

  const targets = getEntityTargets(event);

  if (!targets.length) {
    return { ok: true, updated: 0 };
  }

  let updated = 0;

  for (const target of targets) {
    const ok = await updateEntityState(db, target.kind, target.refId, event);
    if (ok) {
      updated += 1;
    }
  }

  return {
    ok: updated > 0,
    updated
  };
}
