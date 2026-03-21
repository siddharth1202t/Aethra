import { safeNumber, safeString } from "./_api-security.js";
import { redis } from "./_redis.js";

const DEFAULT_MAX_AGE_MS = 2 * 60 * 1000;
const DEFAULT_FUTURE_TOLERANCE_MS = 15 * 1000;
const MAX_NONCE_LENGTH = 200;
const NONCE_TTL_MS = 10 * 60 * 1000;

function sanitizeKeyPart(value = "", maxLength = 200, fallback = "") {
  const cleaned = safeString(value || "", maxLength)
    .trim()
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[^a-zA-Z0-9._:@/-]/g, "");
  return cleaned || fallback;
}

function normalizeNonce(value) {
  return sanitizeKeyPart(value || "", MAX_NONCE_LENGTH, "");
}

function normalizeScope(value) {
  return sanitizeKeyPart(value || "default", 100, "default").toLowerCase();
}

function buildNonceKey(scope, nonce) {
  return `nonce:${normalizeScope(scope)}:${normalizeNonce(nonce)}`;
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

  if (!safeRequestAt || !Number.isFinite(safeRequestAt)) {
    return {
      ok: false,
      code: "missing_request_timestamp",
      ageMs: null,
      now
    };
  }

  // reject absurd timestamps far in the past/future even before age evaluation
  if (safeRequestAt < 1_500_000_000_000 || safeRequestAt > now + 24 * 60 * 60 * 1000) {
    return {
      ok: false,
      code: "invalid_request_timestamp",
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

export async function checkAndStoreNonce({
  nonce,
  scope = "default",
  ttlMs = NONCE_TTL_MS
} = {}) {
  const normalizedNonce = normalizeNonce(nonce);
  const normalizedScope = normalizeScope(scope);
  const safeTtlMs = Math.max(30 * 1000, safeNumber(ttlMs, NONCE_TTL_MS));

  if (!normalizedNonce) {
    return {
      ok: false,
      code: "missing_nonce"
    };
  }

  if (normalizedNonce.length < 8) {
    return {
      ok: false,
      code: "weak_nonce"
    };
  }

  const key = buildNonceKey(normalizedScope, normalizedNonce);
  const ttlSeconds = Math.max(1, Math.ceil(safeTtlMs / 1000));

  try {
    const result = await redis.set(key, "1", {
      nx: true,
      ex: ttlSeconds
    });

    if (result !== "OK") {
      return {
        ok: false,
        code: "replayed_nonce"
      };
    }

    return {
      ok: true,
      code: "stored",
      scope: normalizedScope
    };
  } catch (error) {
    console.error("Redis nonce store failed:", error);

    return {
      ok: false,
      code: "nonce_store_error"
    };
  }
}

export async function validateFreshRequest({
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

  const nonceResult = await checkAndStoreNonce({
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
    now: freshness.now,
    scope: normalizeScope(scope)
  };
}
