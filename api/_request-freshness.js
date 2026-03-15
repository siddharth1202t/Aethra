import { safeNumber, safeString } from "./_api-security.js";

const DEFAULT_MAX_AGE_MS = 2 * 60 * 1000;
const DEFAULT_FUTURE_TOLERANCE_MS = 15 * 1000;
const MAX_NONCE_LENGTH = 200;

const recentNonceStore = new Map();
const NONCE_TTL_MS = 10 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 60 * 1000;

let lastCleanupAt = 0;

function cleanupNonceStore(force = false) {
  const now = Date.now();

  if (!force && now - lastCleanupAt < CLEANUP_INTERVAL_MS) {
    return;
  }

  lastCleanupAt = now;

  for (const [key, value] of recentNonceStore.entries()) {
    if (!value || now - safeNumber(value.createdAt, 0) > NONCE_TTL_MS) {
      recentNonceStore.delete(key);
    }
  }
}

function normalizeNonce(value) {
  return safeString(value || "", MAX_NONCE_LENGTH).trim();
}

export function validateRequestFreshness({
  requestAt,
  maxAgeMs = DEFAULT_MAX_AGE_MS,
  futureToleranceMs = DEFAULT_FUTURE_TOLERANCE_MS
} = {}) {
  const now = Date.now();
  const safeRequestAt = safeNumber(requestAt, 0);
  const safeMaxAgeMs = Math.max(1_000, safeNumber(maxAgeMs, DEFAULT_MAX_AGE_MS));
  const safeFutureToleranceMs = Math.max(
    0,
    safeNumber(futureToleranceMs, DEFAULT_FUTURE_TOLERANCE_MS)
  );

  if (!safeRequestAt) {
    return {
      ok: false,
      code: "missing_request_timestamp",
      ageMs: null,
      now
    };
  }

  const ageMs = now - safeRequestAt;

  if (ageMs < -safeFutureToleranceMs) {
    return {
      ok: false,
      code: "future_request_timestamp",
      ageMs,
      now
    };
  }

  if (ageMs > safeMaxAgeMs) {
    return {
      ok: false,
      code: "stale_request_timestamp",
      ageMs,
      now
    };
  }

  return {
    ok: true,
    code: "fresh",
    ageMs,
    now
  };
}

export function checkAndStoreNonce({
  nonce,
  scope = "default",
  ttlMs = NONCE_TTL_MS
} = {}) {
  cleanupNonceStore();

  const normalizedNonce = normalizeNonce(nonce);
  const normalizedScope = safeString(scope || "default", 100);
  const safeTtlMs = Math.max(30 * 1000, safeNumber(ttlMs, NONCE_TTL_MS));
  const now = Date.now();

  if (!normalizedNonce) {
    return {
      ok: false,
      code: "missing_nonce"
    };
  }

  const key = `${normalizedScope}::${normalizedNonce}`;
  const existing = recentNonceStore.get(key);

  if (existing && now - safeNumber(existing.createdAt, 0) <= safeTtlMs) {
    return {
      ok: false,
      code: "replayed_nonce"
    };
  }

  recentNonceStore.set(key, {
    createdAt: now
  });

  return {
    ok: true,
    code: "stored"
  };
}

export function validateFreshRequest({
  requestAt,
  nonce = "",
  scope = "default",
  requireNonce = false,
  maxAgeMs = DEFAULT_MAX_AGE_MS,
  futureToleranceMs = DEFAULT_FUTURE_TOLERANCE_MS,
  nonceTtlMs = NONCE_TTL_MS
} = {}) {
  const freshness = validateRequestFreshness({
    requestAt,
    maxAgeMs,
    futureToleranceMs
  });

  if (!freshness.ok) {
    return {
      ok: false,
      code: freshness.code,
      ageMs: freshness.ageMs,
      now: freshness.now
    };
  }

  if (!requireNonce) {
    return {
      ok: true,
      code: "fresh",
      ageMs: freshness.ageMs,
      now: freshness.now
    };
  }

  const nonceResult = checkAndStoreNonce({
    nonce,
    scope,
    ttlMs: nonceTtlMs
  });

  if (!nonceResult.ok) {
    return {
      ok: false,
      code: nonceResult.code,
      ageMs: freshness.ageMs,
      now: freshness.now
    };
  }

  return {
    ok: true,
    code: "fresh_with_nonce",
    ageMs: freshness.ageMs,
    now: freshness.now
  };
}
