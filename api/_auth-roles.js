import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { writeSecurityLog } from "./_security-log-writer.js";
import { safeString } from "./_api-security.js";

let adminAuthInstance = null;

function getAdminAuth() {
  if (adminAuthInstance) {
    return adminAuthInstance;
  }

  if (!getApps().length) {
    initializeApp({
      credential: cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n")
      })
    });
  }

  adminAuthInstance = getAuth();
  return adminAuthInstance;
}

function getBearerToken(req) {
  const authHeader = safeString(req?.headers?.authorization || "", 2000);

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return "";
  }

  return safeString(authHeader.slice(7).trim(), 4000);
}

function buildRoleResult({
  ok = false,
  status = 401,
  code = "unauthorized",
  message = "Unauthorized.",
  decodedToken = null,
  claims = {}
} = {}) {
  return {
    ok,
    status,
    code,
    message,
    decodedToken,
    claims
  };
}

export async function verifyRequestToken(req) {
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
    const claims = decodedToken || {};

    return buildRoleResult({
      ok: true,
      status: 200,
      code: "verified",
      message: "Token verified.",
      decodedToken,
      claims
    });
  } catch (error) {
    return buildRoleResult({
      ok: false,
      status: 401,
      code: "invalid_token",
      message: "Invalid or expired token."
    });
  }
}

export function hasDeveloperRole(claims = {}) {
  return claims?.developer === true || claims?.admin === true;
}

export function hasAdminRole(claims = {}) {
  return claims?.admin === true;
}

export async function requireDeveloperAccess(req, {
  route = "unknown-route",
  logDenied = true
} = {}) {
  const tokenResult = await verifyRequestToken(req);

  if (!tokenResult.ok) {
    if (logDenied) {
      await writeSecurityLog({
        type: "developer_access_denied",
        level: "warning",
        message: "Developer access denied due to missing or invalid token",
        route,
        metadata: {
          source: "server_enforced",
          code: tokenResult.code
        }
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
      await writeSecurityLog({
        type: "developer_access_denied",
        level: "warning",
        message: "Developer access denied due to insufficient role",
        userId: safeString(tokenResult.decodedToken?.uid || "", 128),
        route,
        metadata: {
          source: "server_enforced",
          code: "insufficient_role",
          claimsDeveloper: tokenResult.claims?.developer === true,
          claimsAdmin: tokenResult.claims?.admin === true
        }
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
    uid: safeString(tokenResult.decodedToken?.uid || "", 128),
    decodedToken: tokenResult.decodedToken,
    claims: tokenResult.claims
  };
}

export async function requireAdminAccess(req, {
  route = "unknown-route",
  logDenied = true
} = {}) {
  const tokenResult = await verifyRequestToken(req);

  if (!tokenResult.ok) {
    if (logDenied) {
      await writeSecurityLog({
        type: "admin_access_denied",
        level: "warning",
        message: "Admin access denied due to missing or invalid token",
        route,
        metadata: {
          source: "server_enforced",
          code: tokenResult.code
        }
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
      await writeSecurityLog({
        type: "admin_access_denied",
        level: "warning",
        message: "Admin access denied due to insufficient role",
        userId: safeString(tokenResult.decodedToken?.uid || "", 128),
        route,
        metadata: {
          source: "server_enforced",
          code: "insufficient_role",
          claimsAdmin: tokenResult.claims?.admin === true
        }
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
    uid: safeString(tokenResult.decodedToken?.uid || "", 128),
    decodedToken: tokenResult.decodedToken,
    claims: tokenResult.claims
  };
}
