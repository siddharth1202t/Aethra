import { getRedis } from "./_redis.js";

const THREAT_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const THREAT_DECAY_MS = 30 * 60 * 1000;

const MAX_IP_LENGTH = 100;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_USER_ID_LENGTH = 128;
const MAX_ROUTE_LENGTH = 150;
const MAX_REASON_LENGTH = 100;
const MAX_REASON_HISTORY = 50;

const ALLOWED_ROUTE_SENSITIVITY = new Set(["normal", "high", "critical"]);

/* ---------- helpers ---------- */

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
  return safeInt(value, fallback, 0, Date.now() + 60000);
}

function safeJsonParse(raw, fallback = null) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

/* ---------- normalization ---------- */

function sanitizeKeyPart(value = "", maxLength = 120, fallback = "") {
  const cleaned = safeString(value, maxLength)
    .replace(/[^a-zA-Z0-9._:@/-]/g, "");
  return cleaned || fallback;
}

function normalizeIp(value = "") {
  let ip = safeString(value || "unknown", MAX_IP_LENGTH);

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

  const cleaned = raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, MAX_ROUTE_LENGTH);

  return cleaned || "unknown-route";
}

function normalizeRouteSensitivity(value = "normal") {
  const normalized = safeString(value, 20).toLowerCase();
  return ALLOWED_ROUTE_SENSITIVITY.has(normalized)
    ? normalized
    : "normal";
}

function normalizeReason(value = "") {
  return safeString(value || "", MAX_REASON_LENGTH).replace(/[^\w:.-]/g, "_");
}

/* ---------- Redis helpers ---------- */

function buildThreatKey({ ip = "", sessionId = "", userId = "" } = {}) {
  return `threat:${normalizeIp(ip)}::${normalizeSessionId(sessionId)}::${normalizeUserId(userId)}`;
}

function createDefaultThreatRecord(now = Date.now()) {
  return {
    createdAt: now,
    updatedAt: now,
    threatScore: 0,
    highestThreatScore: 0,
    lastRoute: "unknown-route",
    reasonHistory: [],

    blockEvents: 0,
    hardBlockSignals: 0,
    criticalRouteHits: 0,
    exploitSignals: 0,
    breachSignals: 0,
    endpointSpread: 0
  };
}

function normalizeReasonHistory(reasons = []) {
  if (!Array.isArray(reasons)) return [];

  const out = [];
  for (const reason of reasons) {
    const safeReason = normalizeReason(reason);
    if (!safeReason) continue;
    if (!out.includes(safeReason)) out.push(safeReason);
    if (out.length >= MAX_REASON_HISTORY) break;
  }

  return out;
}

function normalizeThreatRecord(raw, now = Date.now()) {
  const record = raw && typeof raw === "object" ? raw : {};
  const base = createDefaultThreatRecord(now);

  return {
    createdAt: safeTimestamp(record.createdAt, base.createdAt),
    updatedAt: safeTimestamp(record.updatedAt, base.updatedAt),
    threatScore: safeInt(record.threatScore, 0, 0, 100),
    highestThreatScore: safeInt(record.highestThreatScore, 0, 0, 100),
    lastRoute: normalizeRoute(record.lastRoute || base.lastRoute),
    reasonHistory: normalizeReasonHistory(record.reasonHistory || []),

    blockEvents: safeInt(record.blockEvents, 0),
    hardBlockSignals: safeInt(record.hardBlockSignals, 0),
    criticalRouteHits: safeInt(record.criticalRouteHits, 0),
    exploitSignals: safeInt(record.exploitSignals, 0),
    breachSignals: safeInt(record.breachSignals, 0),
    endpointSpread: safeInt(record.endpointSpread, 0)
  };
}

async function getStoredThreatRecord(env, redisKey, now) {
  const redis = getRedis(env);

  try {
    const raw = await redis.get(redisKey);

    if (!raw) return null;

    if (typeof raw === "string") {
      return normalizeThreatRecord(safeJsonParse(raw, null), now);
    }

    if (typeof raw === "object") {
      return normalizeThreatRecord(raw, now);
    }

    return null;
  } catch (err) {
    console.error("Threat intelligence read failed:", err);
    return null;
  }
}

async function storeThreatRecord(env, redisKey, record) {
  const redis = getRedis(env);

  try {
    const ttlSeconds = Math.max(1, Math.ceil(THREAT_STATE_TTL_MS / 1000));

    await redis.set(
      redisKey,
      JSON.stringify(normalizeThreatRecord(record, Date.now())),
      { ex: ttlSeconds }
    );

    return true;
  } catch (err) {
    console.error("Threat intelligence write failed:", err);
    return false;
  }
}

function applyThreatDecay(record, now = Date.now()) {
  const updatedAt = safeTimestamp(record.updatedAt, now);
  const elapsed = Math.max(0, now - updatedAt);

  if (elapsed < THREAT_DECAY_MS) {
    return record;
  }

  const windows = Math.floor(elapsed / THREAT_DECAY_MS);
  const decayed = { ...record };

  decayed.threatScore = Math.max(0, safeInt(record.threatScore, 0) - windows * 8);
  decayed.blockEvents = Math.max(0, safeInt(record.blockEvents, 0) - windows);
  decayed.hardBlockSignals = Math.max(0, safeInt(record.hardBlockSignals, 0) - windows);
  decayed.criticalRouteHits = Math.max(0, safeInt(record.criticalRouteHits, 0) - windows);
  decayed.exploitSignals = Math.max(0, safeInt(record.exploitSignals, 0) - windows);
  decayed.breachSignals = Math.max(0, safeInt(record.breachSignals, 0) - windows);
  decayed.endpointSpread = Math.max(0, safeInt(record.endpointSpread, 0) - windows);
  decayed.updatedAt = now;

  return decayed;
}

function pushReasons(record, reasons = []) {
  const merged = [...normalizeReasonHistory(record.reasonHistory || [])];

  for (const reason of reasons) {
    const safeReason = normalizeReason(reason);
    if (!safeReason) continue;
    if (!merged.includes(safeReason)) merged.push(safeReason);
  }

  record.reasonHistory = merged.slice(-MAX_REASON_HISTORY);
}

function getLevel(score = 0) {
  const safeScore = safeInt(score, 0, 0, 100);

  if (safeScore >= 90) return "critical";
  if (safeScore >= 70) return "high";
  if (safeScore >= 40) return "medium";
  return "low";
}

function getAction(score = 0, hardBlockSignals = 0) {
  const safeScore = safeInt(score, 0, 0, 100);
  const safeHardBlockSignals = safeInt(hardBlockSignals, 0, 0, 100);

  if (safeHardBlockSignals >= 2 || safeScore >= 90) return "block";
  if (safeScore >= 70) return "challenge";
  if (safeScore >= 40) return "throttle";
  return "allow";
}

/* ---------- public API ---------- */

export async function evaluateThreat({
  env = {},
  ip = "",
  sessionId = "",
  userId = "",
  route = "",
  routeSensitivity = "normal",
  botResult = null,
  abuseResult = null,
  rateLimitResult = null,
  freshnessResult = null,
  securityState = null
} = {}) {
  const now = Date.now();
  const redisKey = buildThreatKey({ ip, sessionId, userId });

  let record = await getStoredThreatRecord(env, redisKey, now);
  if (!record) {
    record = createDefaultThreatRecord(now);
  }

  record = applyThreatDecay(record, now);
  record.updatedAt = now;
  record.lastRoute = normalizeRoute(route);

  let threatScore = safeInt(record.threatScore, 0, 0, 100);
  const reasons = [];

  const normalizedRouteSensitivity = normalizeRouteSensitivity(routeSensitivity);

  const botRisk = safeInt(botResult?.riskScore, 0, 0, 100);
  const abuseScore = safeInt(abuseResult?.abuseScore, 0, 0, 100);
  const rateViolations = safeInt(rateLimitResult?.violations, 0, 0, 100);
  const replaySignals = safeInt(freshnessResult?.events?.replaySignals, 0, 0, 100);

  const abuseBreachSignals = safeInt(abuseResult?.events?.breachSignals, 0, 0, 100);
  const abuseHardBlockSignals = safeInt(abuseResult?.events?.hardBlockSignals, 0, 0, 100);
  const abuseEndpointSpread = safeInt(abuseResult?.events?.endpointSpread, 0, 0, 100);

  if (botRisk >= 70) {
    threatScore += 18;
    reasons.push("bot_high_risk");
  } else if (botRisk >= 40) {
    threatScore += 8;
    reasons.push("bot_medium_risk");
  }

  if (abuseScore >= 70) {
    threatScore += 20;
    reasons.push("abuse_high_score");
  } else if (abuseScore >= 40) {
    threatScore += 10;
    reasons.push("abuse_medium_score");
  }

  if (rateLimitResult && rateLimitResult.allowed === false) {
    threatScore += 12;
    record.blockEvents += 1;
    reasons.push("rate_limit_exceeded");
  }

  if (rateViolations >= 3) {
    threatScore += 10;
    reasons.push("repeat_rate_limit_violations");
  }

  if (replaySignals > 0) {
    threatScore += 18;
    reasons.push("replay_signal_detected");
  }

  if (abuseHardBlockSignals > 0) {
    record.hardBlockSignals += abuseHardBlockSignals;
    threatScore += 15;
    reasons.push("hard_block_signal");
  }

  if (abuseBreachSignals > 0) {
    record.breachSignals += abuseBreachSignals;
    threatScore += 22;
    reasons.push("breach_signal_detected");
  }

  if (abuseEndpointSpread >= 4) {
    record.endpointSpread += 1;
    threatScore += 12;
    reasons.push("endpoint_spread_detected");
  }

  if (normalizedRouteSensitivity === "critical") {
    record.criticalRouteHits += 1;
    threatScore += 10;
    reasons.push("critical_route_pressure");
  } else if (normalizedRouteSensitivity === "high") {
    threatScore += 5;
    reasons.push("high_route_pressure");
  }

  if (safeInt(securityState?.currentRiskScore, 0, 0, 100) >= 75) {
    threatScore += 10;
    reasons.push("persistent_high_risk_state");
  }

  if (safeString(securityState?.currentRiskLevel || "", 20).toLowerCase() === "critical") {
    threatScore += 15;
    reasons.push("critical_risk_state");
  }

  if (safeInt(securityState?.exploitFlagCount, 0, 0, 100000) > 0) {
    record.exploitSignals += 1;
    threatScore += 20;
    reasons.push("exploit_history_present");
  }

  if (safeInt(securityState?.breachFlagCount, 0, 0, 100000) > 0) {
    record.breachSignals += 1;
    threatScore += 20;
    reasons.push("breach_history_present");
  }

  record.threatScore = Math.min(100, threatScore);
  record.highestThreatScore = Math.max(
    safeInt(record.highestThreatScore, 0, 0, 100),
    record.threatScore
  );

  pushReasons(record, reasons);
  await storeThreatRecord(env, redisKey, record);

  const level = getLevel(record.threatScore);
  const action = getAction(record.threatScore, record.hardBlockSignals);

  return {
    threatScore: record.threatScore,
    level,
    action,
    reasons: normalizeReasonHistory(record.reasonHistory).slice(-10),
    events: {
      blockEvents: safeInt(record.blockEvents, 0, 0, 100),
      hardBlockSignals: safeInt(record.hardBlockSignals, 0, 0, 100),
      criticalRouteHits: safeInt(record.criticalRouteHits, 0, 0, 100),
      exploitSignals: safeInt(record.exploitSignals, 0, 0, 100),
      breachSignals: safeInt(record.breachSignals, 0, 0, 100),
      endpointSpread: safeInt(record.endpointSpread, 0, 0, 100)
    },
    clientKeyPreview: safeString(redisKey.replace(/^threat:/, ""), 24)
  };
}

export async function getThreatSnapshot({
  env = {},
  ip = "",
  sessionId = "",
  userId = ""
} = {}) {
  const redisKey = buildThreatKey({ ip, sessionId, userId });
  const record = await getStoredThreatRecord(env, redisKey, Date.now());

  if (!record) {
    return {
      found: false,
      clientKeyPreview: safeString(redisKey.replace(/^threat:/, ""), 24)
    };
  }

  return {
    found: true,
    threatScore: safeInt(record.threatScore, 0, 0, 100),
    highestThreatScore: safeInt(record.highestThreatScore, 0, 0, 100),
    lastRoute: normalizeRoute(record.lastRoute),
    reasonHistory: normalizeReasonHistory(record.reasonHistory).slice(-10),
    clientKeyPreview: safeString(redisKey.replace(/^threat:/, ""), 24)
  };
}

export async function clearThreatSnapshot({
  env = {},
  ip = "",
  sessionId = "",
  userId = ""
} = {}) {
  const redis = getRedis(env);
  const redisKey = buildThreatKey({ ip, sessionId, userId });

  try {
    await redis.del(redisKey);
    return { ok: true };
  } catch (err) {
    console.error("Threat intelligence delete failed:", err);
    return { ok: false };
  }
}
