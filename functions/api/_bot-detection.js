import { getRedis } from "./_redis.js";
import { appendSecurityEvent } from "./_security-event-store.js";

const BOT_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const BOT_SIGNAL_WINDOW_MS = 30 * 60 * 1000;
const BOT_DECAY_MS = 30 * 60 * 1000;

const MAX_ROUTE_LENGTH = 150;
const MAX_SESSION_ID_LENGTH = 120;
const MAX_IP_LENGTH = 100;
const MAX_USER_ID_LENGTH = 120;
const MAX_USER_AGENT_LENGTH = 500;
const MAX_REASON_LENGTH = 80;
const MAX_REASON_HISTORY = 30;
const MAX_SIGNAL_HISTORY = 40;
const MAX_RETURN_REASONS = 20;

/* -------------------- SAFETY -------------------- */

function toNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function toSafeInt(value, fallback = 0, min = 0, max = 1_000_000_000) {
  const num = Math.floor(toNumber(value, fallback));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function stripControlChars(value = "") {
  return String(value ?? "").replace(/[\u0000-\u001F\u007F]/g, "");
}

function safeString(value, maxLength = 300) {
  return stripControlChars(value || "").trim().slice(0, maxLength);
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

function isPlainObject(value) {
  if (Object.prototype.toString.call(value) !== "[object Object]") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/* -------------------- REQUEST HELPERS -------------------- */

function getHeaderValue(req, name) {
  const headers = req?.headers;
  if (!headers || !name) return "";

  const target = String(name).toLowerCase();

  if (typeof headers.get === "function") {
    return safeString(headers.get(name) || headers.get(target) || "", 1000);
  }

  if (Array.isArray(headers)) {
    for (const entry of headers) {
      if (
        Array.isArray(entry) &&
        entry.length >= 2 &&
        String(entry[0]).toLowerCase() === target
      ) {
        return safeString(entry[1] || "", 1000);
      }
    }
    return "";
  }

  if (isPlainObject(headers)) {
    for (const [key, value] of Object.entries(headers)) {
      if (String(key).toLowerCase() === target) {
        if (Array.isArray(value)) {
          return safeString(value[0] || "", 1000);
        }
        return safeString(value || "", 1000);
      }
    }
  }

  return "";
}

function normalizeRoute(route) {
  const raw = safeString(route || "unknown-route", MAX_ROUTE_LENGTH * 2);
  if (!raw) return "unknown-route";

  const withoutQuery = raw.split("?")[0].split("#")[0];
  const cleaned = withoutQuery
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .trim()
    .toLowerCase()
    .slice(0, MAX_ROUTE_LENGTH);

  return cleaned || "unknown-route";
}

function normalizeSessionId(value = "") {
  return sanitizeKeyPart(value || "no-session", MAX_SESSION_ID_LENGTH, "no-session");
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

function normalizeUserId(value = "") {
  return sanitizeKeyPart(value || "anon-user", MAX_USER_ID_LENGTH, "anon-user");
}

function normalizeUserAgent(value = "") {
  return safeString(value || "", MAX_USER_AGENT_LENGTH);
}

function normalizeAction(value = "") {
  const action = safeString(value || "allow", 20).toLowerCase();
  if (action === "block" || action === "challenge" || action === "throttle") {
    return action;
  }
  return "allow";
}

function normalizeOrigin(value = "") {
  const raw = safeString(value || "", 200);
  if (!raw) return "";

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

function normalizeReferer(value = "") {
  const raw = safeString(value || "", 300);
  if (!raw) return "";

  try {
    return new URL(raw).toString();
  } catch {
    return "";
  }
}

function buildBotKey({ ip = "", sessionId = "", userId = "" } = {}) {
  const safeIp = normalizeIp(ip);
  const safeSessionId = normalizeSessionId(sessionId);
  const safeUserId = normalizeUserId(userId);
  return `bot:${safeIp}::${safeSessionId}::${safeUserId}`;
}

function buildClientKeyPreview({ ip = "", sessionId = "" } = {}) {
  return safeString(
    `${normalizeIp(ip)}:${normalizeSessionId(sessionId).slice(0, 6)}`,
    24
  );
}

function isSuspiciousUserAgent(userAgent) {
  return /headless|phantom|selenium|playwright|puppeteer|crawler|spider|curl|wget|python-requests|httpclient|node-fetch/i.test(
    userAgent
  );
}

function getRouteSensitivity(route) {
  const normalized = normalizeRoute(route);

  if (
    normalized.includes("admin") ||
    normalized.includes("developer") ||
    normalized.includes("login") ||
    normalized.includes("signup") ||
    normalized.includes("verify")
  ) {
    return 2;
  }

  return 1;
}

function getRecommendedAction({
  riskScore,
  telemetryQualityScore,
  hardBlockSignals,
  suspiciousUserAgent = false,
  routeSensitivity = 1
}) {
  if (
    hardBlockSignals > 0 &&
    (suspiciousUserAgent || routeSensitivity >= 2 || riskScore >= 75)
  ) {
    return "block";
  }

  if (hardBlockSignals > 0 || riskScore >= 90) {
    return "block";
  }

  if (riskScore >= 65) {
    return "challenge";
  }

  if (riskScore >= 40 || telemetryQualityScore <= 30) {
    return "throttle";
  }

  return "allow";
}

/* -------------------- STATE -------------------- */

function createEmptyBotRecord(now) {
  return {
    createdAt: now,
    updatedAt: now,
    suspicionScore: 0,
    highestRiskScore: 0,
    hardBlockCount: 0,
    suspiciousCount: 0,
    lastSeenAt: now,
    lastRoute: "unknown-route",
    lastUserAgent: "",
    lastReason: "",
    reasonHistory: [],
    recentSignals: [],
    recentRoutes: [],
    lastDecayAt: now
  };
}

function normalizeBotRecord(raw, now) {
  const record = raw && typeof raw === "object" ? raw : {};

  return {
    createdAt: toSafeInt(record.createdAt, now, 0, now + 60_000),
    updatedAt: toSafeInt(record.updatedAt, now, 0, now + 60_000),
    suspicionScore: toSafeInt(record.suspicionScore, 0, 0, 1000),
    highestRiskScore: toSafeInt(record.highestRiskScore, 0, 0, 100),
    hardBlockCount: toSafeInt(record.hardBlockCount, 0, 0, 1000),
    suspiciousCount: toSafeInt(record.suspiciousCount, 0, 0, 100000),
    lastSeenAt: toSafeInt(record.lastSeenAt, now, 0, now + 60_000),
    lastRoute: normalizeRoute(record.lastRoute || "unknown-route"),
    lastUserAgent: normalizeUserAgent(record.lastUserAgent || ""),
    lastReason: safeString(record.lastReason || "", MAX_REASON_LENGTH),
    reasonHistory: Array.isArray(record.reasonHistory)
      ? [...new Set(
          record.reasonHistory
            .map((item) => safeString(item, MAX_REASON_LENGTH))
            .filter(Boolean)
        )].slice(-MAX_REASON_HISTORY)
      : [],
    recentSignals: Array.isArray(record.recentSignals)
      ? record.recentSignals
          .map((item) => ({
            at: toSafeInt(item?.at, 0, 0, now + 60_000),
            route: normalizeRoute(item?.route || "unknown-route"),
            riskScore: toSafeInt(item?.riskScore, 0, 0, 100),
            hardBlockSignals: toSafeInt(item?.hardBlockSignals, 0, 0, 10),
            recommendedAction: normalizeAction(item?.recommendedAction || "allow")
          }))
          .filter((item) => item.at > 0 && now - item.at <= BOT_SIGNAL_WINDOW_MS)
          .slice(-MAX_SIGNAL_HISTORY)
      : [],
    recentRoutes: Array.isArray(record.recentRoutes)
      ? record.recentRoutes.map((item) => normalizeRoute(item)).slice(-20)
      : [],
    lastDecayAt: toSafeInt(record.lastDecayAt, now, 0, now + 60_000)
  };
}

async function getStoredBotRecord(redis, redisKey, now) {
  try {
    const raw = await redis.get(redisKey);
    if (!raw) return null;

    if (typeof raw === "string") {
      const parsed = safeJsonParse(raw, null);
      if (!parsed || typeof parsed !== "object") return null;
      return normalizeBotRecord(parsed, now);
    }

    if (typeof raw === "object") {
      return normalizeBotRecord(raw, now);
    }

    return null;
  } catch (error) {
    console.error("Redis bot-detection read failed:", error);
    return null;
  }
}

async function storeBotRecord(redis, redisKey, record) {
  try {
    const ttlSeconds = Math.max(1, Math.ceil(BOT_STATE_TTL_MS / 1000));
    const normalized = normalizeBotRecord(record, Date.now());
    await redis.set(redisKey, JSON.stringify(normalized), { ex: ttlSeconds });
    return true;
  } catch (error) {
    console.error("Redis bot-detection write failed:", error);
    return false;
  }
}

function decayBotScore(record, now) {
  const lastDecayAt = toSafeInt(record.lastDecayAt, now, 0, now);
  const elapsed = now - lastDecayAt;

  if (elapsed < BOT_DECAY_MS) return;

  const decaySteps = Math.floor(elapsed / BOT_DECAY_MS);
  if (decaySteps <= 0) return;

  record.suspicionScore = Math.max(
    0,
    toSafeInt(record.suspicionScore, 0) - decaySteps * 8
  );
  record.lastDecayAt = now;
}

function pushReasonHistory(record, reasons = []) {
  if (!Array.isArray(record.reasonHistory)) {
    record.reasonHistory = [];
  }

  for (const reason of reasons) {
    const safeReason = safeString(reason, MAX_REASON_LENGTH);
    if (safeReason && !record.reasonHistory.includes(safeReason)) {
      record.reasonHistory.push(safeReason);
    }
  }

  record.reasonHistory = record.reasonHistory.slice(-MAX_REASON_HISTORY);
}

function pushRecentSignal(record, signal, now) {
  if (!Array.isArray(record.recentSignals)) {
    record.recentSignals = [];
  }

  record.recentSignals.push({
    at: now,
    route: normalizeRoute(signal.route),
    riskScore: toSafeInt(signal.riskScore, 0, 0, 100),
    hardBlockSignals: toSafeInt(signal.hardBlockSignals, 0, 0, 10),
    recommendedAction: normalizeAction(signal.recommendedAction)
  });

  record.recentSignals = record.recentSignals
    .filter((item) => now - toSafeInt(item.at, 0, 0, now) <= BOT_SIGNAL_WINDOW_MS)
    .slice(-MAX_SIGNAL_HISTORY);
}

function pushRecentRoute(record, route) {
  if (!Array.isArray(record.recentRoutes)) {
    record.recentRoutes = [];
  }

  record.recentRoutes.push(normalizeRoute(route));
  record.recentRoutes = record.recentRoutes.slice(-20);
}

function summarizeRecentSignals(record, route) {
  const recentSignals = Array.isArray(record.recentSignals) ? record.recentSignals : [];
  const sameRouteRecent = recentSignals.filter((item) => item.route === route).length;
  const recentChallenges = recentSignals.filter(
    (item) => item.recommendedAction === "challenge" || item.recommendedAction === "block"
  ).length;
  const recentHardBlocks = recentSignals.reduce(
    (sum, item) => sum + toSafeInt(item.hardBlockSignals, 0, 0, 10),
    0
  );

  const uniqueRecentRoutes = new Set(
    (Array.isArray(record.recentRoutes) ? record.recentRoutes : []).map((item) =>
      normalizeRoute(item)
    )
  ).size;

  return {
    sameRouteRecent,
    recentChallenges,
    recentHardBlocks,
    uniqueRecentRoutes
  };
}

function extractRequestUserAgent(req = null) {
  return normalizeUserAgent(getHeaderValue(req, "user-agent"));
}

function extractForwardedIp(req = null) {
  const cfIp = getHeaderValue(req, "cf-connecting-ip");
  if (cfIp) return normalizeIp(cfIp);

  const realIp = getHeaderValue(req, "x-real-ip");
  if (realIp) return normalizeIp(realIp);

  const forwarded = getHeaderValue(req, "x-forwarded-for");
  if (forwarded) return normalizeIp(forwarded.split(",")[0]?.trim());

  return normalizeIp(req?.socket?.remoteAddress || "");
}

/* -------------------- ANALYSIS -------------------- */

export function analyzeBotBehavior(behavior = {}, req = null) {
  const now = Date.now();

  const pageLoadedAt = toSafeInt(behavior.pageLoadedAt, 0, 0, now + 60_000);
  const firstInteractionAt = toSafeInt(behavior.firstInteractionAt, 0, 0, now + 60_000);
  const submitAt = toSafeInt(behavior.submitAt, now, 0, now + 60_000);

  const mouseMoves = toSafeInt(behavior.mouseMoves, 0, 0, 5000);
  const keyPresses = toSafeInt(behavior.keyPresses, 0, 0, 5000);
  const clicks = toSafeInt(behavior.clicks, 0, 0, 5000);
  const touches = toSafeInt(behavior.touches, 0, 0, 5000);
  const scrolls = toSafeInt(behavior.scrolls, 0, 0, 5000);
  const visibilityChanges = toSafeInt(behavior.visibilityChanges, 0, 0, 5000);

  const sessionId = normalizeSessionId(behavior.sessionId || "");
  const route = normalizeRoute(behavior.route || req?.url || "unknown-route");

  const requestUserAgent = extractRequestUserAgent(req);
  const behaviorUserAgent = normalizeUserAgent(behavior.userAgent || "");
  const userAgent = requestUserAgent || behaviorUserAgent;

  const origin = normalizeOrigin(getHeaderValue(req, "origin"));
  const referer = normalizeReferer(getHeaderValue(req, "referer"));

  const totalInteractions = mouseMoves + keyPresses + clicks + touches + scrolls;
  const directInputs = mouseMoves + keyPresses + clicks + touches;

  const timeOnPageMs =
    pageLoadedAt > 0 && submitAt >= pageLoadedAt ? submitAt - pageLoadedAt : 0;

  const timeToFirstInteractionMs =
    firstInteractionAt > 0 &&
    pageLoadedAt > 0 &&
    firstInteractionAt >= pageLoadedAt
      ? firstInteractionAt - pageLoadedAt
      : null;

  let riskScore = 0;
  let telemetryQualityScore = 100;
  let hardBlockSignals = 0;
  const reasons = [];
  const telemetryWarnings = [];
  const routeSensitivity = getRouteSensitivity(route);
  const suspiciousUa = isSuspiciousUserAgent(userAgent);

  if (!sessionId || sessionId === "no-session") {
    riskScore += 10;
    telemetryQualityScore -= 20;
    reasons.push("missing_session_id");
    telemetryWarnings.push("missing_session_id");
  }

  if (pageLoadedAt > 0 && submitAt > 0 && submitAt < pageLoadedAt) {
    riskScore += 30;
    hardBlockSignals += 1;
    reasons.push("invalid_submit_timeline");
  }

  if (
    firstInteractionAt > 0 &&
    pageLoadedAt > 0 &&
    firstInteractionAt < pageLoadedAt
  ) {
    riskScore += 20;
    reasons.push("invalid_interaction_timeline");
  }

  if (submitAt > now + 10_000 || pageLoadedAt > now + 10_000) {
    riskScore += 20;
    reasons.push("future_timestamp_pattern");
  }

  if (timeOnPageMs > 0 && timeOnPageMs < 1200) {
    riskScore += 25 * routeSensitivity;
    reasons.push("submitted_too_fast");
  }

  if (timeOnPageMs > 0 && timeOnPageMs < 2500 && totalInteractions === 0) {
    riskScore += 30 * routeSensitivity;
    reasons.push("no_interaction_before_submit");
  }

  if (timeToFirstInteractionMs !== null && timeToFirstInteractionMs < 100) {
    riskScore += 15;
    reasons.push("interaction_too_fast");
  }

  if (totalInteractions === 0) {
    riskScore += 15;
    reasons.push("zero_interactions");
  }

  if (directInputs === 0) {
    riskScore += 10;
    reasons.push("no_direct_input_signals");
  }

  if (visibilityChanges > 10) {
    riskScore += 10;
    reasons.push("excessive_visibility_changes");
  }

  if (requestUserAgent && behaviorUserAgent && requestUserAgent !== behaviorUserAgent) {
    riskScore += 15;
    reasons.push("user_agent_mismatch");
  }

  if (!requestUserAgent && !behaviorUserAgent) {
    telemetryQualityScore -= 20;
    telemetryWarnings.push("missing_user_agent");
  }

  if (suspiciousUa) {
    riskScore += 45;
    hardBlockSignals += 1;
    reasons.push("suspicious_user_agent");
  }

  if (
    totalInteractions > 0 &&
    timeOnPageMs > 0 &&
    totalInteractions >= 100 &&
    timeOnPageMs < 1500
  ) {
    riskScore += 25;
    reasons.push("interaction_density_too_high");
  }

  if (
    keyPresses > 0 &&
    clicks === 0 &&
    mouseMoves === 0 &&
    touches === 0 &&
    timeOnPageMs > 0 &&
    timeOnPageMs < 1500
  ) {
    riskScore += 15;
    reasons.push("unnatural_input_pattern");
  }

  if (pageLoadedAt === 0) {
    telemetryQualityScore -= 20;
    telemetryWarnings.push("missing_page_loaded_at");
  }

  if (submitAt === 0) {
    telemetryQualityScore -= 20;
    telemetryWarnings.push("missing_submit_at");
  }

  if (firstInteractionAt === 0 && totalInteractions > 0) {
    telemetryQualityScore -= 10;
    telemetryWarnings.push("missing_first_interaction_at");
  }

  if (!origin) {
    telemetryQualityScore -= 5;
    telemetryWarnings.push("missing_origin");
    if (routeSensitivity >= 2) {
      riskScore += 5;
      reasons.push("missing_origin_high_risk_route");
    }
  }

  if (!referer) {
    telemetryQualityScore -= 5;
    telemetryWarnings.push("missing_referer");
    if (routeSensitivity >= 2) {
      riskScore += 5;
      reasons.push("missing_referer_high_risk_route");
    }
  }

  telemetryQualityScore = Math.max(0, Math.min(100, telemetryQualityScore));
  riskScore = Math.min(100, riskScore);

  let level = "low";
  if (riskScore >= 70) {
    level = "high";
  } else if (riskScore >= 40) {
    level = "medium";
  }

  const recommendedAction = getRecommendedAction({
    riskScore,
    telemetryQualityScore,
    hardBlockSignals,
    suspiciousUserAgent: suspiciousUa,
    routeSensitivity
  });

  return {
    riskScore,
    level,
    recommendedAction,
    telemetryQualityScore,
    hardBlockSignals,
    reasons: reasons.slice(0, MAX_RETURN_REASONS),
    telemetryWarnings,
    events: {
      botSignals: reasons.length > 0 ? 1 : 0,
      hardBlockSignals,
      coordinatedSignals: 0,
      exploitSignals: 0,
      breachSignals: 0,
      replaySignals: 0
    },
    signals: {
      route,
      routeSensitivity,
      timeOnPageMs,
      timeToFirstInteractionMs,
      totalInteractions,
      directInputs,
      mouseMoves,
      keyPresses,
      clicks,
      touches,
      scrolls,
      visibilityChanges,
      sessionIdPresent: Boolean(sessionId && sessionId !== "no-session"),
      requestUserAgentPresent: Boolean(requestUserAgent),
      behaviorUserAgentPresent: Boolean(behaviorUserAgent),
      suspiciousUserAgent: suspiciousUa,
      originPresent: Boolean(origin),
      refererPresent: Boolean(referer)
    }
  };
}

/* -------------------- TRACKING -------------------- */

export async function trackBotBehavior(behavior = {}, req = null, context = {}) {
  const now = Date.now();
  const analysis = analyzeBotBehavior(behavior, req);

  const route = normalizeRoute(behavior.route || req?.url || "unknown-route");
  const requestUserAgent = extractRequestUserAgent(req);
  const behaviorUserAgent = normalizeUserAgent(behavior.userAgent || "");
  const userAgent = requestUserAgent || behaviorUserAgent;

  const sessionId = normalizeSessionId(context.sessionId || behavior.sessionId || "");
  const ip = normalizeIp(context.ip || extractForwardedIp(req) || "");
  const userId = normalizeUserId(context.userId || "");
  const redisKey = buildBotKey({ ip, sessionId, userId });
  const redis = getRedis(context.env || {});

  let record = await getStoredBotRecord(redis, redisKey, now);
  if (!record) {
    record = createEmptyBotRecord(now);
  }

  decayBotScore(record, now);

  let scoreIncrease = 0;

  if (analysis.riskScore >= 70) {
    scoreIncrease += 20;
  } else if (analysis.riskScore >= 40) {
    scoreIncrease += 10;
  } else if (analysis.riskScore >= 20) {
    scoreIncrease += 4;
  }

  if (analysis.hardBlockSignals > 0) {
    scoreIncrease += analysis.hardBlockSignals * 20;
  }

  if (analysis.telemetryQualityScore <= 30) {
    scoreIncrease += 10;
  } else if (analysis.telemetryQualityScore <= 50) {
    scoreIncrease += 5;
  }

  const recentSummary = summarizeRecentSignals(record, route);

  if (recentSummary.sameRouteRecent >= 5) {
    scoreIncrease += 8;
  }

  if (recentSummary.recentChallenges >= 3) {
    scoreIncrease += 10;
  }

  if (recentSummary.recentHardBlocks >= 2) {
    scoreIncrease += 15;
  }

  if (recentSummary.uniqueRecentRoutes >= 4) {
    scoreIncrease += 10;
  }

  if (analysis.recommendedAction === "block" && analysis.riskScore >= 90) {
    scoreIncrease += 20;
  }

  record.suspicionScore = Math.min(
    1000,
    toSafeInt(record.suspicionScore, 0, 0, 1000) + scoreIncrease
  );

  record.highestRiskScore = Math.max(
    toSafeInt(record.highestRiskScore, 0, 0, 100),
    toSafeInt(analysis.riskScore, 0, 0, 100)
  );

  if (analysis.hardBlockSignals > 0) {
    record.hardBlockCount =
      toSafeInt(record.hardBlockCount, 0, 0, 1000) + analysis.hardBlockSignals;
  }

  if (analysis.riskScore >= 40) {
    record.suspiciousCount =
      toSafeInt(record.suspiciousCount, 0, 0, 100000) + 1;
  }

  record.updatedAt = now;
  record.lastSeenAt = now;
  record.lastRoute = route;
  record.lastUserAgent = userAgent;
  record.lastReason = safeString(analysis.reasons[0] || "", MAX_REASON_LENGTH);
  record.lastDecayAt = record.lastDecayAt || now;

  pushReasonHistory(record, analysis.reasons);
  pushRecentSignal(
    record,
    {
      route,
      riskScore: analysis.riskScore,
      hardBlockSignals: analysis.hardBlockSignals,
      recommendedAction: analysis.recommendedAction
    },
    now
  );
  pushRecentRoute(record, route);

  await storeBotRecord(redis, redisKey, record);

  let escalatedAction = analysis.recommendedAction;
  let coordinatedSignals = 0;

  if (recentSummary.uniqueRecentRoutes >= 4) {
    coordinatedSignals = 1;
  }

  if (record.hardBlockCount >= 2 || record.suspicionScore >= 120) {
    escalatedAction = "block";
  } else if (record.suspicionScore >= 90 || record.suspiciousCount >= 5) {
    escalatedAction = "challenge";
  } else if (
    escalatedAction === "allow" &&
    (record.suspicionScore >= 60 || record.suspiciousCount >= 3)
  ) {
    escalatedAction = "throttle";
  }

  if (
    escalatedAction === "block" ||
    (analysis.hardBlockSignals > 0 && analysis.riskScore >= 70)
  ) {
    try {
      await appendSecurityEvent(context.env || {}, {
        type: "bot_detection_escalated",
        severity: escalatedAction === "block" ? "critical" : "warning",
        action: escalatedAction === "block" ? "block" : escalatedAction,
        route,
        ip,
        userId: userId || "",
        reason: safeString(analysis.reasons[0] || "bot_escalation", 120),
        message: "Bot detection escalated for actor.",
        metadata: {
          actorKey: safeString(redisKey.replace(/^bot:/, ""), 240),
          suspicionScore: toSafeInt(record.suspicionScore, 0, 0, 1000),
          highestRiskScore: toSafeInt(record.highestRiskScore, 0, 0, 100),
          hardBlockCount: toSafeInt(record.hardBlockCount, 0, 0, 1000),
          suspiciousCount: toSafeInt(record.suspiciousCount, 0, 0, 100000),
          coordinatedSignals,
          clientKeyPreview: buildClientKeyPreview({ ip, sessionId })
        }
      });
    } catch (error) {
      console.error("Bot detection event write failed:", error);
    }
  }

  return {
    ...analysis,
    escalatedAction,
    events: {
      ...analysis.events,
      coordinatedSignals
    },
    distributed: {
      suspicionScore: toSafeInt(record.suspicionScore, 0, 0, 1000),
      highestRiskScore: toSafeInt(record.highestRiskScore, 0, 0, 100),
      hardBlockCount: toSafeInt(record.hardBlockCount, 0, 0, 1000),
      suspiciousCount: toSafeInt(record.suspiciousCount, 0, 0, 100000),
      sameRouteRecent: recentSummary.sameRouteRecent,
      recentChallenges: recentSummary.recentChallenges,
      recentHardBlocks: recentSummary.recentHardBlocks,
      uniqueRecentRoutes: recentSummary.uniqueRecentRoutes,
      clientKeyPreview: buildClientKeyPreview({ ip, sessionId })
    }
  };
}

export async function getBotBehaviorSnapshot(context = {}) {
  const now = Date.now();
  const ip = context.ip || "";
  const sessionId = context.sessionId || "";
  const userId = context.userId || "";

  const redisKey = buildBotKey({
    ip,
    sessionId,
    userId
  });

  const redis = getRedis(context.env || {});
  const record = await getStoredBotRecord(redis, redisKey, now);

  if (!record) {
    return {
      found: false,
      clientKeyPreview: buildClientKeyPreview({ ip, sessionId })
    };
  }

  return {
    found: true,
    clientKeyPreview: buildClientKeyPreview({ ip, sessionId }),
    suspicionScore: toSafeInt(record.suspicionScore, 0, 0, 1000),
    highestRiskScore: toSafeInt(record.highestRiskScore, 0, 0, 100),
    hardBlockCount: toSafeInt(record.hardBlockCount, 0, 0, 1000),
    suspiciousCount: toSafeInt(record.suspiciousCount, 0, 0, 100000),
    lastSeenAt: toSafeInt(record.lastSeenAt, 0, 0, now + 60_000),
    lastRoute: normalizeRoute(record.lastRoute || "unknown-route"),
    updatedAt: toSafeInt(record.updatedAt, 0, 0, now + 60_000),
    lastReason: safeString(record.lastReason || "", MAX_REASON_LENGTH)
  };
}

export async function clearBotBehaviorSnapshot(context = {}) {
  const redisKey = buildBotKey({
    ip: context.ip || "",
    sessionId: context.sessionId || "",
    userId: context.userId || ""
  });
  const redis = getRedis(context.env || {});

  try {
    await redis.del(redisKey);
    return { ok: true };
  } catch (error) {
    console.error("Redis bot-detection delete failed:", error);
    return { ok: false };
  }
}
