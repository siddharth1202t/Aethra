import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { writeSecurityLog } from "./_security-log-writer.js";
import { safeString as baseSafeString } from "./_api-security.js";

let adminAuthInstance = null;

function safeString(value, maxLength = 300) {
  return baseSafeString(
    String(value || "").replace(/[\u0000-\u001F\u007F]/g, ""),
    maxLength
  );
}

function normalizeRoute(route = "") {
  const raw = safeString(route || "unknown-route", 300);
  if (!raw) return "unknown-route";

  const cleaned = raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_-]/g, "")
    .toLowerCase()
    .slice(0, 150);

  return cleaned || "unknown-route";
}

function getRequiredEnv(name) {
  return safeString(process.env[name] || "", 5000);
}

function ensureAdminEnv() {
  const projectId = getRequiredEnv("FIREBASE_PROJECT_ID");
  const clientEmail = getRequiredEnv("FIREBASE_CLIENT_EMAIL");
  const privateKeyRaw = process.env.FIREBASE_PRIVATE_KEY || "";
  const privateKey = String(privateKeyRaw).replace(/\\n/g, "\n").trim();

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error("Missing Firebase Admin credentials.");
  }

  return {
    projectId,
    clientEmail,
    privateKey
  };
}

function getAdminAuth() {
  if (adminAuthInstance) {
    return adminAuthInstance;
  }

  if (!getApps().length) {
    const creds = ensureAdminEnv();

    initializeApp({
      credential: cert({
        projectId: creds.projectId,
        clientEmail: creds.clientEmail,
        privateKey: creds.privateKey
      })
    });
  }

  adminAuthInstance = getAuth();
  return adminAuthInstance;
}

function getBearerToken(req) {
  const authHeader = safeString(req?.headers?.authorization || "", 5000);

  if (!authHeader) {
    return "";
  }

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return "";
  }

  const token = safeString(match[1] || "", 4000);

  // basic JWT shape sanity check
  if (!token || token.split(".").length !== 3) {
    return "";
  }

  return token;
}

function sanitizeClaims(claims = {}) {
  return {
    admin: claims?.admin === true,
    developer: claims?.developer === true,
    email_verified: claims?.email_verified === true,
    uid: safeString(claims?.uid || "", 128)
  };
}

function buildRoleResult({
  ok = false,
  status = 401,
  code = "unauthorized",
  message = "Unauthorized.",
  decodedToken = null,
  claims = {},
  uid = "",
  emailVerified = false,
  disabled = false
} = {}) {
  return {
    ok,
    status,
    code,
    message,
    decodedToken,
    claims,
    uid: safeString(uid || "", 128),
    emailVerified: emailVerified === true,
    disabled: disabled === true
  };
}

async function checkUserDisabled(adminAuth, uid) {
  try {
    const safeUid = safeString(uid || "", 128);
    if (!safeUid) return false;

    const userRecord = await adminAuth.getUser(safeUid);
    return userRecord?.disabled === true;
  } catch {
    // fail open on lookup issue, token verification is still primary
    return false;
  }
}

export async function verifyRequestToken(req, { requireEmailVerified = false } = {}) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return buildRoleResult({
        ok: false,
        status: 401,
        code: "missing_token",
        message: "Missing authorization token."
      });
    }

    const adminAuth = getAdminAuth();
    const decodedToken = await adminAuth.verifyIdToken(token, true);
    const claims = sanitizeClaims(decodedToken || {});
    const uid = safeString(decodedToken?.uid || "", 128);
    const emailVerified = decodedToken?.email_verified === true;
    const disabled = await checkUserDisabled(adminAuth, uid);

    if (disabled) {
      return buildRoleResult({
        ok: false,
        status: 403,
        code: "disabled_user",
        message: "User account is disabled.",
        decodedToken: null,
        claims,
        uid,
        emailVerified,
        disabled: true
      });
    }

    if (requireEmailVerified && !emailVerified) {
      return buildRoleResult({
        ok: false,
        status: 403,
        code: "email_not_verified",
        message: "Verified email required.",
        decodedToken,
        claims,
        uid,
        emailVerified,
        disabled: false
      });
    }

    return buildRoleResult({
      ok: true,
      status: 200,
      code: "verified",
      message: "Token verified.",
      decodedToken,
      claims,
      uid,
      emailVerified,
      disabled: false
    });
  } catch (error) {
    const message = safeString(error?.message || "", 200);

    const code =
      message.includes("Firebase Admin credentials")
        ? "server_auth_not_configured"
        : "invalid_token";

    const status = code === "server_auth_not_configured" ? 500 : 401;
    const responseMessage =
      code === "server_auth_not_configured"
        ? "Server authentication is not configured."
        : "Invalid or expired token.";

    return buildRoleResult({
      ok: false,
      status,
      code,
      message: responseMessage
    });
  }
}

export function hasDeveloperRole(claims = {}) {
  return claims?.developer === true || claims?.admin === true;
}

export function hasAdminRole(claims = {}) {
  return claims?.admin === true;
}

async function logDeniedAccess({
  type = "privileged_access_denied",
  route = "unknown-route",
  tokenResult = null,
  message = "Access denied.",
  code = "unauthorized"
} = {}) {
  try {
    await writeSecurityLog({
      type: safeString(type, 50),
      level: "warning",
      message: safeString(message, 300),
      userId: safeString(tokenResult?.uid || tokenResult?.decodedToken?.uid || "", 128),
      route: normalizeRoute(route),
      metadata: {
        source: "server_enforced",
        code: safeString(code || tokenResult?.code || "unauthorized", 50),
        claimsDeveloper: tokenResult?.claims?.developer === true,
        claimsAdmin: tokenResult?.claims?.admin === true,
        emailVerified: tokenResult?.emailVerified === true,
        disabled: tokenResult?.disabled === true
      }
    });
  } catch {
    // never break auth flow because logging failed
  }
}

export async function requireDeveloperAccess(
  req,
  {
    route = "unknown-route",
    logDenied = true,
    requireEmailVerified = true
  } = {}
) {
  const normalizedRoute = normalizeRoute(route);
  const tokenResult = await verifyRequestToken(req, { requireEmailVerified });

  if (!tokenResult.ok) {
    if (logDenied) {
      await logDeniedAccess({
        type: "developer_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Developer access denied due to missing, invalid, disabled, or unverified token",
        code: tokenResult.code
      });
    }

    return {
      ok: false,
      status: tokenResult.status,
      code: tokenResult.code,
      message: tokenResult.message
    };
  }

  if (!hasDeveloperRole(tokenResult.claims)) {
    if (logDenied) {
      await logDeniedAccess({
        type: "developer_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Developer access denied due to insufficient role",
        code: "insufficient_role"
      });
    }

    return {
      ok: false,
      status: 403,
      code: "insufficient_role",
      message: "Developer access required."
    };
  }

  return {
    ok: true,
    status: 200,
    code: "authorized",
    message: "Developer access granted.",
    uid: safeString(tokenResult.uid || "", 128),
    decodedToken: tokenResult.decodedToken,
    claims: tokenResult.claims,
    emailVerified: tokenResult.emailVerified
  };
}

export async function requireAdminAccess(
  req,
  {
    route = "unknown-route",
    logDenied = true,
    requireEmailVerified = true
  } = {}
) {
  const normalizedRoute = normalizeRoute(route);
  const tokenResult = await verifyRequestToken(req, { requireEmailVerified });

  if (!tokenResult.ok) {
    if (logDenied) {
      await logDeniedAccess({
        type: "admin_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Admin access denied due to missing, invalid, disabled, or unverified token",
        code: tokenResult.code
      });
    }

    return {
      ok: false,
      status: tokenResult.status,
      code: tokenResult.code,
      message: tokenResult.message
    };
  }

  if (!hasAdminRole(tokenResult.claims)) {
    if (logDenied) {
      await logDeniedAccess({
        type: "admin_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Admin access denied due to insufficient role",
        code: "insufficient_role"
      });
    }

    return {
      ok: false,
      status: 403,
      code: "insufficient_role",
      message: "Admin access required."
    };
  }

  return {
    ok: true,
    status: 200,
    code: "authorized",
    message: "Admin access granted.",
    uid: safeString(tokenResult.uid || "", 128),
    decodedToken: tokenResult.decodedToken,
    claims: tokenResult.claims,
    emailVerified: tokenResult.emailVerified
  };
}
