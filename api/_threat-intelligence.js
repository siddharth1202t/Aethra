import { redis } from "./_redis.js";

const THREAT_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const THREAT_DECAY_MS = 30 * 60 * 1000;

const MAX_IP_LENGTH = 100;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_USER_ID_LENGTH = 128;
const MAX_ROUTE_LENGTH = 150;
const MAX_REASON_LENGTH = 100;
const MAX_REASON_HISTORY = 50;

function safeString(value, maxLength = 300) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function safeInt(value, fallback = 0, min = 0, max = 1_000_000) {
  const num = Math.floor(safeNumber(value, fallback));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function safeTimestamp(value, fallback = 0) {
  return safeInt(value, fallback, 0, Date.now() + 60_000);
}

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function sanitizeKeyPart(value = "", maxLength = 120, fallback = "") {
  const cleaned = safeString(value, maxLength).replace(/[^a-zA-Z0-9._:@/-]/g, "");
  return cleaned || fallback;
}

function normalizeIp(value = "") {
  let ip = safeString(value || "unknown", MAX_IP_LENGTH);

  if (!ip) return "unknown";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, MAX_IP_LENGTH);

  return ip || "unknown";
}

function normalizeSessionId(value = "") {
  return sanitizeKeyPart(value || "no-session", MAX_SESSION_ID_LENGTH, "no-session");
}

function normalizeUserId(value = "") {
  return sanitizeKeyPart(value || "anon-user", MAX_USER_ID_LENGTH, "anon-user");
}

function normalizeRoute(value = "") {
  const raw = safeString(value || "unknown-route", MAX_ROUTE_LENGTH * 2);

  if (!raw) return "unknown-route";

  const cleaned = raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_-]/g, "")
    .toLowerCase()
    .slice(0, MAX_ROUTE_LENGTH);

  return cleaned || "unknown-route";
}

function normalizeAction(value = "") {
  const normalized = safeString(value || "allow", 20).toLowerCase();
  if (normalized === "block" || normalized === "challenge" || normalized === "throttle") {
    return normalized;
  }
  return "allow";
}

function buildThreatKey({ ip = "", sessionId = "", userId = "" } = {}) {
  return `threat:${normalizeIp(ip)}::${normalizeSessionId(sessionId)}::${normalizeUserId(userId)}`;
}

function createEmptyThreatRecord(now) {
  return {
    createdAt: now,
    updatedAt: now,
    lastDecayAt: now,

    threatScore: 0,
    highestThreatScore: 0,

    botEvents: 0,
    abuseEvents: 0,
    rateLimitEvents: 0,
    freshnessFailures: 0,

    hardBlockSignals: 0,
    challengeEvents: 0,
    blockEvents: 0,
    criticalRouteHits: 0,

    lastRoute: "unknown-route",
    reasonHistory: []
  };
}

function normalizeThreatRecord(raw, now) {
  const record = raw && typeof raw === "object" ? raw : {};

  return {
    createdAt: safeTimestamp(record.createdAt, now),
    updatedAt: safeTimestamp(record.updatedAt, now),
    lastDecayAt: safeTimestamp(record.lastDecayAt, now),

    threatScore: safeInt(record.threatScore, 0, 0, 100),
    highestThreatScore: safeInt(record.highestThreatScore, 0, 0, 100),

    botEvents: safeInt(record.botEvents, 0, 0, 100000),
    abuseEvents: safeInt(record.abuseEvents, 0, 0, 100000),
    rateLimitEvents: safeInt(record.rateLimitEvents, 0, 0, 100000),
    freshnessFailures: safeInt(record.freshnessFailures, 0, 0, 100000),

    hardBlockSignals: safeInt(record.hardBlockSignals, 0, 0, 100000),
    challengeEvents: safeInt(record.challengeEvents, 0, 0, 100000),
    blockEvents: safeInt(record.blockEvents, 0, 0, 100000),
    criticalRouteHits: safeInt(record.criticalRouteHits, 0, 0, 100000),

    lastRoute: normalizeRoute(record.lastRoute || "unknown-route"),
    reasonHistory: Array.isArray(record.reasonHistory)
      ? [...new Set(
          record.reasonHistory
            .map((item) => safeString(item, MAX_REASON_LENGTH))
            .filter(Boolean)
        )].slice(-MAX_REASON_HISTORY)
      : []
  };
}

async function getStoredThreatRecord(redisKey, now) {
  try {
    const raw = await redis.get(redisKey);

    if (!raw) {
      return null;
    }

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      if (!parsed || typeof parsed !== "object") {
        return null;
      }
      return normalizeThreatRecord(parsed, now);
    }

    if (typeof raw === "object") {
      return normalizeThreatRecord(raw, now);
    }

    return null;
  } catch (error) {
    console.error("Threat intelligence read failed:", error);
    return null;
  }
}

async function storeThreatRecord(redisKey, record) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(THREAT_STATE_TTL_MS / 1000));
    const normalized = normalizeThreatRecord(record, Date.now());
    await redis.set(redisKey, JSON.stringify(normalized), { ex: ttlSeconds });
    return true;
  } catch (error) {
    console.error("Threat intelligence write failed:", error);
    return false;
  }
}

function pushReason(record, reason) {
  const safeReason = safeString(reason, MAX_REASON_LENGTH);
  if (!safeReason) return;

  if (!Array.isArray(record.reasonHistory)) {
    record.reasonHistory = [];
  }

  if (!record.reasonHistory.includes(safeReason)) {
    record.reasonHistory.push(safeReason);
  }

  record.reasonHistory = record.reasonHistory.slice(-MAX_REASON_HISTORY);
}

function decayThreatScore(record, now) {
  const lastDecayAt = safeTimestamp(record.lastDecayAt, now);
  const elapsed = now - lastDecayAt;

  if (elapsed < THREAT_DECAY_MS) {
    return;
  }

  const steps = Math.floor(elapsed / THREAT_DECAY_MS);
  if (steps <= 0) {
    return;
  }

  record.threatScore = Math.max(0, safeInt(record.threatScore, 0, 0, 100) - steps * 6);
  record.lastDecayAt = now;
}

function getThreatLevel(score) {
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function getThreatAction(score, hardBlockSignals = 0) {
  if (hardBlockSignals > 0 || score >= 95) return "block";
  if (score >= 75) return "challenge";
  if (score >= 45) return "throttle";
  return "allow";
}

export async function evaluateThreat({
  ip = "",
  sessionId = "",
  userId = "",
  route = "",
  botResult = null,
  abuseResult = null,
  rateLimitResult = null,
  freshnessResult = null,
  riskResult = null
} = {}) {
  const now = Date.now();
  const redisKey = buildThreatKey({ ip, sessionId, userId });

  let record = await getStoredThreatRecord(redisKey, now);
  if (!record) {
    record = createEmptyThreatRecord(now);
  }

  decayThreatScore(record, now);

  let scoreIncrease = 0;
  const safeRoute = normalizeRoute(route);

  if (botResult && typeof botResult === "object") {
    record.botEvents += 1;

    if (safeInt(botResult.riskScore, 0, 0, 100) >= 70) {
      scoreIncrease += 20;
      pushReason(record, "bot_high_risk");
    } else if (safeInt(botResult.riskScore, 0, 0, 100) >= 40) {
      scoreIncrease += 10;
      pushReason(record, "bot_medium_risk");
    }

    if (safeInt(botResult.hardBlockSignals, 0, 0, 20) > 0) {
      record.hardBlockSignals += safeInt(botResult.hardBlockSignals, 0, 0, 20);
      scoreIncrease += 25;
      pushReason(record, "bot_hard_block_signal");
    }

    if (safeInt(botResult?.distributed?.sensitiveRouteHits, 0, 0, 100000) >= 5) {
      scoreIncrease += 10;
      pushReason(record, "bot_sensitive_route_targeting");
    }

    if (safeInt(botResult?.distributed?.hardBlockCount, 0, 0, 100000) >= 2) {
      record.hardBlockSignals += 1;
      scoreIncrease += 15;
      pushReason(record, "bot_distributed_hard_block_history");
    }
  }

  if (abuseResult && typeof abuseResult === "object") {
    record.abuseEvents += 1;

    if (safeInt(abuseResult.abuseScore, 0, 0, 100) >= 70) {
      scoreIncrease += 18;
      pushReason(record, "abuse_high_score");
    } else if (safeInt(abuseResult.abuseScore, 0, 0, 100) >= 40) {
      scoreIncrease += 8;
      pushReason(record, "abuse_medium_score");
    }

    if (abuseResult.penaltyActive) {
      scoreIncrease += 15;
      pushReason(record, "abuse_penalty_active");
    }

    if (safeInt(abuseResult?.snapshot?.criticalRouteTouchesRecent, 0, 0, 100000) >= 2) {
      record.criticalRouteHits += 1;
      scoreIncrease += 15;
      pushReason(record, "abuse_critical_route_targeting");
    }
  }

  if (rateLimitResult && typeof rateLimitResult === "object") {
    record.rateLimitEvents += 1;

    if (!rateLimitResult.allowed) {
      scoreIncrease += 12;
      pushReason(record, "rate_limit_exceeded");
    }

    if (rateLimitResult.penaltyActive) {
      scoreIncrease += 12;
      pushReason(record, "rate_limit_penalty_active");
    }

    if (safeInt(rateLimitResult.violations, 0, 0, 100000) >= 4) {
      scoreIncrease += 10;
      pushReason(record, "rate_limit_repeat_violations");
    }
  }

  if (freshnessResult && typeof freshnessResult === "object" && !freshnessResult.ok) {
    record.freshnessFailures += 1;
    scoreIncrease += 20;
    pushReason(record, `freshness_${safeString(freshnessResult.code || "failed", 60)}`);

    if (
      freshnessResult.code === "replayed_nonce" ||
      freshnessResult.code === "future_request_timestamp"
    ) {
      record.hardBlockSignals += 1;
    }
  }

  if (riskResult && typeof riskResult === "object") {
    const normalizedRiskAction = normalizeAction(riskResult.action || "");

    if (normalizedRiskAction === "challenge") {
      record.challengeEvents += 1;
    }

    if (normalizedRiskAction === "block") {
      record.blockEvents += 1;
      scoreIncrease += 20;
      pushReason(record, "risk_engine_block");
    }

    if (safeInt(riskResult.riskScore, 0, 0, 100) >= 80) {
      scoreIncrease += 10;
      pushReason(record, "risk_engine_high_score");
    }
  }

  if (
    botResult &&
    abuseResult &&
    safeInt(botResult.riskScore, 0, 0, 100) >= 40 &&
    safeInt(abuseResult.abuseScore, 0, 0, 100) >= 40
  ) {
    scoreIncrease += 12;
    pushReason(record, "cross_signal_bot_plus_abuse");
  }

  if (safeRoute.includes("admin") || safeRoute.includes("developer")) {
    record.criticalRouteHits += 1;
  }

  if (record.criticalRouteHits >= 5) {
    scoreIncrease += 10;
    pushReason(record, "repeat_critical_route_pressure");
  }

  if (record.freshnessFailures >= 3) {
    scoreIncrease += 10;
    pushReason(record, "repeat_freshness_failures");
  }

  if (record.blockEvents >= 2) {
    scoreIncrease += 15;
    pushReason(record, "repeat_block_events");
  }

  record.threatScore = Math.min(100, safeInt(record.threatScore, 0, 0, 100) + scoreIncrease);
  record.highestThreatScore = Math.max(
    safeInt(record.highestThreatScore, 0, 0, 100),
    record.threatScore
  );

  record.updatedAt = now;
  record.lastRoute = safeRoute;

  await storeThreatRecord(redisKey, record);

  const level = getThreatLevel(record.threatScore);
  const action = getThreatAction(record.threatScore, record.hardBlockSignals);

  return {
    threatScore: record.threatScore,
    level,
    action,
    events: {
      botEvents: safeInt(record.botEvents, 0, 0, 100000),
      abuseEvents: safeInt(record.abuseEvents, 0, 0, 100000),
      rateLimitEvents: safeInt(record.rateLimitEvents, 0, 0, 100000),
      freshnessFailures: safeInt(record.freshnessFailures, 0, 0, 100000),
      hardBlockSignals: safeInt(record.hardBlockSignals, 0, 0, 100000),
      challengeEvents: safeInt(record.challengeEvents, 0, 0, 100000),
      blockEvents: safeInt(record.blockEvents, 0, 0, 100000),
      criticalRouteHits: safeInt(record.criticalRouteHits, 0, 0, 100000)
    },
    clientKeyPreview: safeString(redisKey.replace(/^threat:/, ""), 24),
    lastRoute: record.lastRoute,
    highestThreatScore: safeInt(record.highestThreatScore, 0, 0, 100),
    recentReasons: Array.isArray(record.reasonHistory)
      ? record.reasonHistory.slice(-10)
      : []
  };
}

export async function getThreatSnapshot({
  ip = "",
  sessionId = "",
  userId = ""
} = {}) {
  const now = Date.now();
  const redisKey = buildThreatKey({ ip, sessionId, userId });
  const record = await getStoredThreatRecord(redisKey, now);

  if (!record) {
    return {
      found: false,
      clientKeyPreview: safeString(redisKey.replace(/^threat:/, ""), 24)
    };
  }

  return {
    found: true,
    clientKeyPreview: safeString(redisKey.replace(/^threat:/, ""), 24),
    threatScore: safeInt(record.threatScore, 0, 0, 100),
    highestThreatScore: safeInt(record.highestThreatScore, 0, 0, 100),
    updatedAt: safeTimestamp(record.updatedAt, 0),
    lastRoute: normalizeRoute(record.lastRoute || "unknown-route"),
    events: {
      botEvents: safeInt(record.botEvents, 0, 0, 100000),
      abuseEvents: safeInt(record.abuseEvents, 0, 0, 100000),
      rateLimitEvents: safeInt(record.rateLimitEvents, 0, 0, 100000),
      freshnessFailures: safeInt(record.freshnessFailures, 0, 0, 100000),
      hardBlockSignals: safeInt(record.hardBlockSignals, 0, 0, 100000),
      blockEvents: safeInt(record.blockEvents, 0, 0, 100000)
    }
  };
}

export async function clearThreatSnapshot({
  ip = "",
  sessionId = "",
  userId = ""
} = {}) {
  const redisKey = buildThreatKey({ ip, sessionId, userId });

  try {
    await redis.del(redisKey);
    return { ok: true };
  } catch (error) {
    console.error("Threat intelligence delete failed:", error);
    return { ok: false };
  }
}
