import { writeSecurityLog } from "./_security-log-writer.js";
import { safeString as baseSafeString } from "./_api-security.js";

const FIREBASE_JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

const GOOGLE_ISSUER_PREFIX = "https://securetoken.google.com/";
const DEFAULT_JWKS_CACHE_TTL_MS = 60 * 60 * 1000;
const MAX_CLOCK_SKEW_SECONDS = 300;

let jwksCache = {
  keys: null,
  expiresAt: 0
};

function safeString(value, maxLength = 300) {
  return baseSafeString(
    String(value ?? "").replace(/[\u0000-\u001F\u007F]/g, ""),
    maxLength
  );
}

function safeInt(value, fallback = 0, min = 0, max = 1_000_000_000) {
  const num = Math.floor(Number(value));
  if (!Number.isFinite(num)) return fallback;
  return Math.min(max, Math.max(min, num));
}

function normalizeRoute(route = "") {
  const raw = safeString(route || "unknown-route", 300);
  if (!raw) return "unknown-route";

  const cleaned = raw
    .split("?")[0]
    .split("#")[0]
    .replace(/\/{2,}/g, "/")
    .replace(/[^a-zA-Z0-9/_:-]/g, "")
    .toLowerCase()
    .slice(0, 150);

  return cleaned || "unknown-route";
}

function getRequiredEnv(env = {}, name, maxLength = 5000) {
  return safeString(env?.[name] || "", maxLength);
}

function ensureProjectId(env = {}) {
  const projectId = getRequiredEnv(env, "FIREBASE_PROJECT_ID", 200);
  if (!projectId) {
    throw new Error("Missing Firebase project ID.");
  }
  return projectId;
}

function getHeaderValue(req, name) {
  const headers = req?.headers;
  if (!headers || !name) return "";

  const target = String(name).toLowerCase();

  if (typeof headers.get === "function") {
    return safeString(headers.get(name) || headers.get(target) || "", 5000);
  }

  if (Array.isArray(headers)) {
    for (const entry of headers) {
      if (
        Array.isArray(entry) &&
        entry.length >= 2 &&
        String(entry[0]).toLowerCase() === target
      ) {
        return safeString(entry[1] || "", 5000);
      }
    }
    return "";
  }

  for (const [key, value] of Object.entries(headers || {})) {
    if (String(key).toLowerCase() === target) {
      return safeString(value, 5000);
    }
  }

  return "";
}

function getBearerToken(req) {
  const authHeader = getHeaderValue(req, "authorization");
  if (!authHeader) return "";

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return "";

  const token = safeString(match[1] || "", 4000);
  return token && token.split(".").length === 3 ? token : "";
}

function normalizeIp(value = "") {
  let ip = safeString(value || "unknown", 100);
  if (!ip) return "unknown";

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  ip = ip.replace(/[^a-fA-F0-9:.,]/g, "").slice(0, 100);
  return ip || "unknown";
}

function getClientIp(req) {
  const cfIp = getHeaderValue(req, "cf-connecting-ip");
  if (cfIp) return normalizeIp(cfIp);

  const realIp = getHeaderValue(req, "x-real-ip");
  if (realIp) return normalizeIp(realIp);

  const forwarded = getHeaderValue(req, "x-forwarded-for");
  if (forwarded) return normalizeIp(forwarded.split(",")[0] || "");

  return normalizeIp(req?.ip || req?.socket?.remoteAddress || "");
}

function getOrigin(req) {
  const raw = getHeaderValue(req, "origin");
  if (!raw) return "";

  try {
    return new URL(raw).origin.toLowerCase();
  } catch {
    return "";
  }
}

function sanitizeClaims(claims = {}) {
  return {
    admin: claims?.admin === true,
    developer: claims?.developer === true || claims?.admin === true,
    email_verified: claims?.email_verified === true,
    uid: safeString(claims?.uid || claims?.sub || "", 128)
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
    code: safeString(code, 60),
    message: safeString(message, 300),
    decodedToken,
    claims,
    uid: safeString(uid || "", 128),
    emailVerified: emailVerified === true,
    disabled: disabled === true
  };
}

function base64UrlToUint8Array(value = "") {
  const normalized = String(value || "")
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(String(value || "").length / 4) * 4, "=");

  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function decodeJwtPart(part = "") {
  const bytes = base64UrlToUint8Array(part);
  const json = new TextDecoder().decode(bytes);
  return JSON.parse(json);
}

function parseJwt(token = "") {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format.");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = decodeJwtPart(encodedHeader);
  const payload = decodeJwtPart(encodedPayload);

  const alg = safeString(header?.alg || "", 20);
  const typ = safeString(header?.typ || "", 20);
  const kid = safeString(header?.kid || "", 200);

  if (alg !== "RS256") {
    throw new Error("Unsupported JWT algorithm.");
  }

  if (typ && typ !== "JWT") {
    throw new Error("Invalid JWT type.");
  }

  if (!kid) {
    throw new Error("JWT missing key ID.");
  }

  return {
    encodedHeader,
    encodedPayload,
    encodedSignature,
    signedData: `${encodedHeader}.${encodedPayload}`,
    header,
    payload
  };
}

function getCacheTtlMs(response) {
  const cacheControl = safeString(response?.headers?.get?.("cache-control") || "", 500);
  const match = cacheControl.match(/max-age=(\d+)/i);
  if (!match) return DEFAULT_JWKS_CACHE_TTL_MS;

  const seconds = safeInt(match[1], 3600, 1, 24 * 3600);
  return seconds * 1000;
}

async function getFirebaseJwks() {
  const now = Date.now();

  if (jwksCache.keys && jwksCache.expiresAt > now) {
    return jwksCache.keys;
  }

  const response = await fetch(FIREBASE_JWKS_URL, {
    method: "GET",
    headers: { accept: "application/json" }
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Failed to fetch Firebase JWKs: ${response.status} ${safeString(text, 300)}`
    );
  }

  const data = await response.json();
  const keys = Array.isArray(data?.keys) ? data.keys : [];

  if (!keys.length) {
    throw new Error("Firebase JWKs response missing keys.");
  }

  jwksCache = {
    keys,
    expiresAt: now + getCacheTtlMs(response)
  };

  return keys;
}

async function importJwkForVerify(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function verifyJwtSignature(token = "") {
  const parsed = parseJwt(token);
  const kid = safeString(parsed.header?.kid || "", 200);

  const jwks = await getFirebaseJwks();
  const jwk = jwks.find((key) => safeString(key?.kid || "", 200) === kid);

  if (!jwk) {
    throw new Error("Matching JWT verification key not found.");
  }

  const cryptoKey = await importJwkForVerify(jwk);
  const signatureBytes = base64UrlToUint8Array(parsed.encodedSignature);
  const signedDataBytes = new TextEncoder().encode(parsed.signedData);

  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    signatureBytes,
    signedDataBytes
  );

  if (!verified) {
    throw new Error("JWT signature verification failed.");
  }

  return parsed.payload;
}

function validateDecodedToken(decodedToken = {}, projectId = "") {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const issuer = `${GOOGLE_ISSUER_PREFIX}${projectId}`;

  if (!decodedToken || typeof decodedToken !== "object") {
    throw new Error("Decoded token is invalid.");
  }

  const aud = safeString(decodedToken.aud || "", 300);
  const iss = safeString(decodedToken.iss || "", 500);
  const sub = safeString(decodedToken.sub || "", 128);
  const uid = safeString(
    decodedToken.user_id || decodedToken.uid || decodedToken.sub || "",
    128
  );
  const exp = safeInt(decodedToken.exp, 0, 0, 9_999_999_999);
  const iat = safeInt(decodedToken.iat, 0, 0, 9_999_999_999);
  const authTime = safeInt(decodedToken.auth_time, 0, 0, 9_999_999_999);

  if (aud !== projectId) {
    throw new Error("Token audience mismatch.");
  }

  if (iss !== issuer) {
    throw new Error("Token issuer mismatch.");
  }

  if (!sub || sub.length > 128) {
    throw new Error("Token subject is invalid.");
  }

  if (!uid) {
    throw new Error("Token user ID is missing.");
  }

  if (!exp || nowSeconds >= exp) {
    throw new Error("Token is expired.");
  }

  if (iat && iat > nowSeconds + MAX_CLOCK_SKEW_SECONDS) {
    throw new Error("Token issued-at time is invalid.");
  }

  if (authTime && authTime > nowSeconds + MAX_CLOCK_SKEW_SECONDS) {
    throw new Error("Token auth_time is invalid.");
  }

  return {
    ...decodedToken,
    uid,
    user_id: uid
  };
}

async function verifyFirebaseIdToken(env = {}, token = "") {
  const projectId = ensureProjectId(env);
  const decodedToken = await verifyJwtSignature(token);
  return validateDecodedToken(decodedToken, projectId);
}

export function hasDeveloperRole(claims = {}) {
  return claims?.developer === true || claims?.admin === true;
}

export function hasAdminRole(claims = {}) {
  return claims?.admin === true;
}

async function logDeniedAccess({
  env = {},
  req = null,
  type = "privileged_access_denied",
  route = "unknown-route",
  tokenResult = null,
  message = "Access denied.",
  code = "unauthorized"
} = {}) {
  try {
    await writeSecurityLog({
      env,
      type: safeString(type, 50),
      level: "warning",
      message: safeString(message, 300),
      userId: safeString(tokenResult?.uid || "", 128),
      ip: getClientIp(req),
      route: normalizeRoute(route),
      metadata: {
        source: "server_enforced",
        code: safeString(code || tokenResult?.code || "unauthorized", 50),
        claimsDeveloper: tokenResult?.claims?.developer === true,
        claimsAdmin: tokenResult?.claims?.admin === true,
        emailVerified: tokenResult?.emailVerified === true,
        disabled: tokenResult?.disabled === true,
        origin: getOrigin(req)
      }
    });
  } catch {
    // do not break auth flow on log failure
  }
}

export async function verifyRequestToken(
  req,
  { env = {}, requireEmailVerified = false } = {}
) {
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

    const decodedToken = await verifyFirebaseIdToken(env, token);
    const claims = sanitizeClaims(decodedToken || {});
    const uid = safeString(decodedToken?.uid || "", 128);
    const emailVerified = decodedToken?.email_verified === true;

    if (requireEmailVerified && !emailVerified) {
      return buildRoleResult({
        ok: false,
        status: 403,
        code: "email_not_verified",
        message: "Verified email required.",
        decodedToken: null,
        claims,
        uid,
        emailVerified
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
      emailVerified
    });
  } catch (error) {
    const message = safeString(error?.message || "", 200);

    const code =
      message.includes("Firebase project ID")
        ? "server_auth_not_configured"
        : "invalid_token";

    return buildRoleResult({
      ok: false,
      status: code === "server_auth_not_configured" ? 500 : 401,
      code,
      message:
        code === "server_auth_not_configured"
          ? "Server authentication is not configured."
          : "Invalid or expired token."
    });
  }
}

export async function requireDeveloperAccess(
  req,
  {
    env = {},
    route = "unknown-route",
    logDenied = true,
    requireEmailVerified = true
  } = {}
) {
  const normalizedRoute = normalizeRoute(route);
  const tokenResult = await verifyRequestToken(req, {
    env,
    requireEmailVerified
  });

  if (!tokenResult.ok) {
    if (logDenied) {
      await logDeniedAccess({
        env,
        req,
        type: "developer_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Developer access denied.",
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
        env,
        req,
        type: "developer_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Developer access denied due to insufficient role.",
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
    env = {},
    route = "unknown-route",
    logDenied = true,
    requireEmailVerified = true
  } = {}
) {
  const normalizedRoute = normalizeRoute(route);
  const tokenResult = await verifyRequestToken(req, {
    env,
    requireEmailVerified
  });

  if (!tokenResult.ok) {
    if (logDenied) {
      await logDeniedAccess({
        env,
        req,
        type: "admin_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Admin access denied.",
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
        env,
        req,
        type: "admin_access_denied",
        route: normalizedRoute,
        tokenResult,
        message: "Admin access denied due to insufficient role.",
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
