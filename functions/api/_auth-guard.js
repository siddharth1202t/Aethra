import {
  verifyRequestToken,
  requireAdminAccess,
  requireDeveloperAccess
} from "./_auth-roles.js";
import {
  buildDeniedResponse,
  buildBlockedResponse,
  safeString
} from "./_api-security.js";

const DEFAULT_CONTENT_TYPE = "application/json; charset=utf-8";

/* -------------------- RESPONSE HELPERS -------------------- */

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": DEFAULT_CONTENT_TYPE,
      "cache-control": "no-store",
      "pragma": "no-cache",
      "x-content-type-options": "nosniff"
    }
  });
}

function buildAuthErrorResponse(result = {}) {
  const code = safeString(result?.code || "unauthorized", 60);
  const message = safeString(result?.message || "Unauthorized.", 300);

  if (
    code === "account_locked" ||
    code === "actor_blocked" ||
    code === "auth_contained"
  ) {
    return {
      status: 403,
      body: buildBlockedResponse(message, {
        action: "block",
        code
      })
    };
  }

  if (code === "session_revoked") {
    return {
      status: 401,
      body: buildDeniedResponse(message, {
        action: "deny",
        code
      })
    };
  }

  if (code === "email_not_verified") {
    return {
      status: 403,
      body: buildDeniedResponse(message, {
        action: "deny",
        code
      })
    };
  }

  if (code === "server_auth_not_configured") {
    return {
      status: 500,
      body: buildDeniedResponse(message, {
        action: "deny",
        code
      })
    };
  }

  if (code === "insufficient_role") {
    return {
      status: 403,
      body: buildDeniedResponse(message, {
        action: "deny",
        code
      })
    };
  }

  return {
    status: result?.status || 401,
    body: buildDeniedResponse(message, {
      action: "deny",
      code
    })
  };
}

function attachAuthContext(context = {}, auth = {}) {
  const next = context || {};

  next.auth = {
    uid: safeString(auth?.uid || "", 128),
    claims: auth?.claims || {},
    emailVerified: auth?.emailVerified === true,
    decodedToken: auth?.decodedToken || null,
    containment: auth?.containment || null
  };

  next.user = {
    uid: safeString(auth?.uid || "", 128),
    claims: auth?.claims || {},
    emailVerified: auth?.emailVerified === true
  };

  return next;
}

/* -------------------- CORE GUARDS -------------------- */

export async function requireAuthenticatedUser(
  req,
  {
    env = {},
    route = "unknown-route",
    requireEmailVerified = false
  } = {}
) {
  const authResult = await verifyRequestToken(req, {
    env,
    requireEmailVerified,
    route
  });

  if (!authResult.ok) {
    const response = buildAuthErrorResponse(authResult);

    return {
      ok: false,
      status: response.status,
      code: authResult.code,
      message: authResult.message,
      containment: authResult.containment || null,
      response: jsonResponse(response.body, response.status)
    };
  }

  return {
    ok: true,
    status: 200,
    code: authResult.code,
    message: authResult.message,
    uid: authResult.uid,
    decodedToken: authResult.decodedToken,
    claims: authResult.claims,
    emailVerified: authResult.emailVerified,
    containment: authResult.containment || null,
    auth: {
      uid: authResult.uid,
      decodedToken: authResult.decodedToken,
      claims: authResult.claims,
      emailVerified: authResult.emailVerified,
      containment: authResult.containment || null
    }
  };
}

export async function requireVerifiedUser(
  req,
  {
    env = {},
    route = "unknown-route"
  } = {}
) {
  return requireAuthenticatedUser(req, {
    env,
    route,
    requireEmailVerified: true
  });
}

export async function requireDeveloperUser(
  req,
  {
    env = {},
    route = "unknown-route",
    logDenied = true,
    requireEmailVerified = true
  } = {}
) {
  const authResult = await requireDeveloperAccess(req, {
    env,
    route,
    logDenied,
    requireEmailVerified
  });

  if (!authResult.ok) {
    const response = buildAuthErrorResponse(authResult);

    return {
      ok: false,
      status: response.status,
      code: authResult.code,
      message: authResult.message,
      containment: authResult.containment || null,
      response: jsonResponse(response.body, response.status)
    };
  }

  return {
    ok: true,
    status: 200,
    code: authResult.code,
    message: authResult.message,
    uid: authResult.uid,
    decodedToken: authResult.decodedToken,
    claims: authResult.claims,
    emailVerified: authResult.emailVerified,
    containment: authResult.containment || null,
    auth: {
      uid: authResult.uid,
      decodedToken: authResult.decodedToken,
      claims: authResult.claims,
      emailVerified: authResult.emailVerified,
      containment: authResult.containment || null
    }
  };
}

export async function requireAdminUser(
  req,
  {
    env = {},
    route = "unknown-route",
    logDenied = true,
    requireEmailVerified = true
  } = {}
) {
  const authResult = await requireAdminAccess(req, {
    env,
    route,
    logDenied,
    requireEmailVerified
  });

  if (!authResult.ok) {
    const response = buildAuthErrorResponse(authResult);

    return {
      ok: false,
      status: response.status,
      code: authResult.code,
      message: authResult.message,
      containment: authResult.containment || null,
      response: jsonResponse(response.body, response.status)
    };
  }

  return {
    ok: true,
    status: 200,
    code: authResult.code,
    message: authResult.message,
    uid: authResult.uid,
    decodedToken: authResult.decodedToken,
    claims: authResult.claims,
    emailVerified: authResult.emailVerified,
    containment: authResult.containment || null,
    auth: {
      uid: authResult.uid,
      decodedToken: authResult.decodedToken,
      claims: authResult.claims,
      emailVerified: authResult.emailVerified,
      containment: authResult.containment || null
    }
  };
}

/* -------------------- CONTEXT HELPERS -------------------- */

export async function withAuthenticatedUser(
  context,
  options = {}
) {
  const result = await requireAuthenticatedUser(context?.request, {
    env: context?.env || {},
    route: options?.route || context?.request?.url || "unknown-route",
    requireEmailVerified: options?.requireEmailVerified === true
  });

  if (!result.ok) {
    return result;
  }

  attachAuthContext(context, result.auth);
  return result;
}

export async function withVerifiedUser(
  context,
  options = {}
) {
  return withAuthenticatedUser(context, {
    ...options,
    requireEmailVerified: true
  });
}

export async function withDeveloperUser(
  context,
  options = {}
) {
  const result = await requireDeveloperUser(context?.request, {
    env: context?.env || {},
    route: options?.route || context?.request?.url || "unknown-route",
    logDenied: options?.logDenied !== false,
    requireEmailVerified: options?.requireEmailVerified !== false
  });

  if (!result.ok) {
    return result;
  }

  attachAuthContext(context, result.auth);
  return result;
}

export async function withAdminUser(
  context,
  options = {}
) {
  const result = await requireAdminUser(context?.request, {
    env: context?.env || {},
    route: options?.route || context?.request?.url || "unknown-route",
    logDenied: options?.logDenied !== false,
    requireEmailVerified: options?.requireEmailVerified !== false
  });

  if (!result.ok) {
    return result;
  }

  attachAuthContext(context, result.auth);
  return result;
}
