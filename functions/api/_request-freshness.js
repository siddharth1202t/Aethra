import { safeNumber, safeString } from "./_api-security.js";
import { getRedis } from "./_redis.js";

const DEFAULT_MAX_AGE_MS = 2 * 60 * 1000;
const DEFAULT_FUTURE_TOLERANCE_MS = 15 * 1000;
const MIN_REQUEST_TIMESTAMP_MS = 1_500_000_000_000;
const MAX_REQUEST_FUTURE_SKEW_MS = 24 * 60 * 60 * 1000;

const MAX_NONCE_LENGTH = 200;
const MIN_NONCE_LENGTH = 8;
const NONCE_TTL_MS = 10 * 60 * 1000;
const MIN_NONCE_TTL_MS = 30 * 1000;

function sanitizeKeyPart(value = "", maxLength = 200, fallback = "") {
  const cleaned = safeString(value || "", maxLength)
    .trim()
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[^a-zA-Z0-9._:@/-]/g, "");

  return cleaned || fallback;
}

function normalizeNonce(value = "") {
  return sanitizeKeyPart(value || "", MAX_NONCE_LENGTH, "");
}

function normalizeScope(value = "") {
  return sanitizeKeyPart(value || "default", 100, "default").toLowerCase();
}

function normalizeTtlMs(value, fallback = NONCE_TTL_MS) {
  return Math.max(MIN_NONCE_TTL_MS, safeNumber(value, fallback));
}

function normalizeMaxAgeMs(value, fallback = DEFAULT_MAX_AGE_MS) {
  return Math.max(1_000, safeNumber(value, fallback));
}

function normalizeFutureToleranceMs(value, fallback = DEFAULT_FUTURE_TOLERANCE_MS) {
  return Math.max(0, safeNumber(value, fallback));
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
  const safeMaxAgeMs = normalizeMaxAgeMs(maxAgeMs, DEFAULT_MAX_AGE_MS);
  const safeFutureToleranceMs = normalizeFutureToleranceMs(
    futureToleranceMs,
    DEFAULT_FUTURE_TOLERANCE_MS
  );

  if (!safeRequestAt || !Number.isFinite(safeRequestAt)) {
    return {
      ok: false,
      code: "missing_request_timestamp",
      ageMs: null,
      now
    };
  }

  if (
    safeRequestAt < MIN_REQUEST_TIMESTAMP_MS ||
    safeRequestAt > now + MAX_REQUEST_FUTURE_SKEW_MS
  ) {
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
  env = {},
  nonce,
  scope = "default",
  ttlMs = NONCE_TTL_MS
} = {}) {
  const normalizedNonce = normalizeNonce(nonce);
  const normalizedScope = normalizeScope(scope);
  const safeTtlMs = normalizeTtlMs(ttlMs, NONCE_TTL_MS);
  const redis = getRedis(env);

  if (!normalizedNonce) {
    return {
      ok: false,
      code: "missing_nonce"
    };
  }

  if (normalizedNonce.length < MIN_NONCE_LENGTH) {
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
        code: "replayed_nonce",
        scope: normalizedScope
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
      code: "nonce_store_error",
      scope: normalizedScope
    };
  }
}

export async function validateFreshRequest({
  env = {},
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
    env,
    nonce,
    scope,
    ttlMs: nonceTtlMs
  });

  if (!nonceResult.ok) {
    return {
      ok: false,
      code: nonceResult.code,
      ageMs: freshness.ageMs,
      now: freshness.now,
      scope: nonceResult.scope || normalizeScope(scope)
    };
  }

  return {
    ok: true,
    code: "fresh_with_nonce",
    ageMs: freshness.ageMs,
    now: freshness.now,
    scope: nonceResult.scope || normalizeScope(scope)
  };
}
