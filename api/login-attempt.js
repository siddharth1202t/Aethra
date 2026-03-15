import { writeSecurityLog } from "./_security-log.js";

const loginAttemptStore = new Map();
const ipAttemptStore = new Map();

const MAX_ATTEMPTS = 5;
const MAX_IP_ATTEMPTS = 20;

const LOCK_WINDOW_MS = 15 * 60 * 1000;
const IP_LOCK_WINDOW_MS = 10 * 60 * 1000;

const STALE_RECORD_TTL_MS = 24 * 60 * 60 * 1000;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getClientIp(req) {

  const forwarded = req.headers["x-forwarded-for"];

  if (typeof forwarded === "string") {
    const parts = forwarded.split(",");
    const ip = parts[0]?.trim();

    if (ip && ip.length < 60) return ip;
  }

  const realIp = req.headers["x-real-ip"];
  if (typeof realIp === "string" && realIp.length < 60) {
    return realIp.trim();
  }

  return "unknown";
}

function getKey(email, ip) {
  return `${email}::${ip}`;
}

function cleanupStaleRecords() {
  const now = Date.now();

  for (const [key, record] of loginAttemptStore.entries()) {
    if (now - record.lastAttempt > STALE_RECORD_TTL_MS) {
      loginAttemptStore.delete(key);
    }
  }

  for (const [ip, record] of ipAttemptStore.entries()) {
    if (now - record.lastAttempt > STALE_RECORD_TTL_MS) {
      ipAttemptStore.delete(ip);
    }
  }
}

function getRecord(store, key) {
  const now = Date.now();
  const record = store.get(key);

  if (!record) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now
    };
  }

  if (record.lockUntil && now > record.lockUntil) {
    return {
      count: 0,
      lockUntil: 0,
      lastAttempt: now
    };
  }

  return record;
}

function saveRecord(store, key, record) {
  store.set(key, record);
}

function isAllowedOrigin(origin) {

  const allowedOrigins = [
    "https://aethra-gules.vercel.app",
    "https://aethra-hb2h.vercel.app"
  ];

  return allowedOrigins.includes(origin);
}

export default async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).json({ success: false });
  }

  try {

    cleanupStaleRecords();

    const origin = req.headers.origin || "";
    const ip = getClientIp(req);

    if (!isAllowedOrigin(origin)) {

      await writeSecurityLog({
        type: "forbidden_origin",
        level: "warning",
        message: "Blocked request from forbidden origin",
        ip,
        route: "/api/login-attempt",
        metadata: { origin }
      });

      return res.status(403).json({ success: false });
    }

    const { email, action } = req.body || {};
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail || !isValidEmail(normalizedEmail)) {

      await writeSecurityLog({
        type: "invalid_login_request",
        level: "warning",
        message: "Invalid email sent to login attempt API",
        email: normalizedEmail,
        ip
      });

      return res.status(400).json({ success: false });
    }

    if (!["check", "fail"].includes(action)) {

      await writeSecurityLog({
        type: "invalid_login_action",
        level: "warning",
        message: "Invalid action sent",
        email: normalizedEmail,
        ip,
        metadata: { action }
      });

      return res.status(400).json({ success: false });
    }

    const now = Date.now();

    /* ---------- GLOBAL IP LIMIT ---------- */

    const ipRecord = getRecord(ipAttemptStore, ip);

    if (ipRecord.lockUntil > now) {

      return res.status(200).json({
        success: true,
        isLocked: true,
        remainingMs: ipRecord.lockUntil - now
      });

    }

    /* ---------- EMAIL + IP LIMIT ---------- */

    const key = getKey(normalizedEmail, ip);
    const record = getRecord(loginAttemptStore, key);

    if (action === "check") {

      const isLocked = record.lockUntil > now;

      return res.status(200).json({
        success: true,
        isLocked,
        remainingMs: isLocked ? record.lockUntil - now : 0
      });
    }

    if (action === "fail") {

      record.count += 1;
      record.lastAttempt = now;

      ipRecord.count += 1;
      ipRecord.lastAttempt = now;

      /* EMAIL LOCK */

      if (record.count >= MAX_ATTEMPTS) {

        record.lockUntil = now + LOCK_WINDOW_MS;

        await writeSecurityLog({
          type: "login_lockout",
          level: "critical",
          message: "Too many login attempts",
          email: normalizedEmail,
          ip,
          metadata: { attempts: record.count }
        });

      }

      /* IP LOCK */

      if (ipRecord.count >= MAX_IP_ATTEMPTS) {

        ipRecord.lockUntil = now + IP_LOCK_WINDOW_MS;

        await writeSecurityLog({
          type: "ip_login_lock",
          level: "critical",
          message: "IP temporarily blocked due to excessive login attempts",
          ip
        });

      }

      saveRecord(loginAttemptStore, key, record);
      saveRecord(ipAttemptStore, ip, ipRecord);

      const isLocked = record.lockUntil > now;

      return res.status(200).json({
        success: true,
        isLocked,
        remainingMs: isLocked ? record.lockUntil - now : 0,
        attempts: record.count
      });
    }

    return res.status(400).json({ success: false });

  } catch (error) {

    console.error("Login attempt API error:", error);

    await writeSecurityLog({
      type: "login_attempt_api_error",
      level: "error",
      message: "Unhandled server error",
      metadata: { error: error?.message }
    });

    return res.status(500).json({
      success: false
    });
  }
}
