import { safeNumber, safeString } from "./_api-security.js";
import { getRedis, isRedisAvailable } from "./_redis.js";

const DEFAULT_MAX_AGE_MS = 2 * 60 * 1000;
const DEFAULT_FUTURE_TOLERANCE_MS = 15 * 1000;
const MIN_REQUEST_TIMESTAMP_MS = 1_500_000_000_000;
const MAX_REQUEST_FUTURE_SKEW_MS = 24 * 60 * 60 * 1000;

const MAX_NONCE_LENGTH = 200;
const MIN_NONCE_LENGTH = 12;
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

function isWeakNonce(nonce = "") {
  const value = normalizeNonce(nonce);

  if (!value || value.length < MIN_NONCE_LENGTH) {
    return true;
  }

  // very low-complexity nonce detection
  const uniqueChars = new Set(value.split("")).size;
  if (uniqueChars < 4) {
    return true;
  }

  // repeated same-char strings like aaaaaaaa1111
  if (/^(.)\1{7,}$/.test(value)) {
    return true;
  }

  return false;
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
      now,
      events: {
        freshnessSignals: 1,
        replaySignals: 0
      }
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
      now,
      events: {
        freshnessSignals: 1,
        replaySignals: 0
      }
    };
  }

  const ageMs = now - safeRequestAt;

  if (ageMs < -safeFutureToleranceMs) {
    return {
      ok: false,
      code: "future_request_timestamp",
      ageMs,
      now,
      events: {
        freshnessSignals: 1,
        replaySignals: 0
      }
    };
  }

  if (ageMs > safeMaxAgeMs) {
    return {
      ok: false,
      code: "stale_request_timestamp",
      ageMs,
      now,
      events: {
        freshnessSignals: 1,
        replaySignals: 0
      }
    };
  }

  return {
    ok: true,
    code: "fresh",
    ageMs,
    now,
    events: {
      freshnessSignals: 0,
      replaySignals: 0
    }
  };
}

export async function checkAndStoreNonce({
  env = {},
  nonce,
  scope = "default",
  ttlMs = NONCE_TTL_MS,
  requireStorage = true
} = {}) {
  const normalizedNonce = normalizeNonce(nonce);
  const normalizedScope = normalizeScope(scope);
  const safeTtlMs = normalizeTtlMs(ttlMs, NONCE_TTL_MS);

  if (!normalizedNonce) {
    return {
      ok: false,
      code: "missing_nonce",
      scope: normalizedScope,
      events: {
        freshnessSignals: 0,
        replaySignals: 1
      }
    };
  }

  if (isWeakNonce(normalizedNonce)) {
    return {
      ok: false,
      code: "weak_nonce",
      scope: normalizedScope,
      events: {
        freshnessSignals: 0,
        replaySignals: 1
      }
    };
  }

  if (!isRedisAvailable(env)) {
    return {
      ok: !requireStorage ? true : false,
      code: requireStorage ? "nonce_storage_unavailable" : "nonce_storage_skipped",
      scope: normalizedScope,
      events: {
        freshnessSignals: 0,
        replaySignals: requireStorage ? 1 : 0
      }
    };
  }

  const redis = getRedis(env);
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
        scope: normalizedScope,
        events: {
          freshnessSignals: 0,
          replaySignals: 1
        }
      };
    }

    return {
      ok: true,
      code: "stored",
      scope: normalizedScope,
      events: {
        freshnessSignals: 0,
        replaySignals: 0
      }
    };
  } catch (error) {
    console.error("Redis nonce store failed:", error);

    return {
      ok: false,
      code: "nonce_store_error",
      scope: normalizedScope,
      events: {
        freshnessSignals: 0,
        replaySignals: 1
      }
    };
  }
}

export async function validateFreshRequest({
  env = {},
  requestAt,
  nonce = "",
  scope = "default",
  requireNonce = false,
  requireNonceStorage = true,
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
      now: freshness.now,
      events: freshness.events
    };
  }

  if (!requireNonce) {
    return {
      ok: true,
      code: "fresh",
      ageMs: freshness.ageMs,
      now: freshness.now,
      events: freshness.events
    };
  }

  const nonceResult = await checkAndStoreNonce({
    env,
    nonce,
    scope,
    ttlMs: nonceTtlMs,
    requireStorage: requireNonceStorage
  });

  if (!nonceResult.ok) {
    return {
      ok: false,
      code: nonceResult.code,
      ageMs: freshness.ageMs,
      now: freshness.now,
      scope: nonceResult.scope || normalizeScope(scope),
      events: nonceResult.events || {
        freshnessSignals: 0,
        replaySignals: 1
      }
    };
  }

  return {
    ok: true,
    code: "fresh_with_nonce",
    ageMs: freshness.ageMs,
    now: freshness.now,
    scope: nonceResult.scope || normalizeScope(scope),
    events: {
      freshnessSignals: 0,
      replaySignals: 0
    }
  };
}
