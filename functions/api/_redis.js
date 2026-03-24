import { Redis } from "@upstash/redis";

let redisInstance = null;
let redisInitSignature = "";
let redisInitAttempted = false;

function safeString(value, maxLength = 500) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function getEnvValue(env = {}, key = "") {
  if (env && typeof env === "object" && env[key] !== undefined) {
    return safeString(env[key], 2000);
  }

  if (typeof process !== "undefined" && process?.env?.[key] !== undefined) {
    return safeString(process.env[key], 2000);
  }

  return "";
}

function getRedisConfig(env = {}) {
  const url = getEnvValue(env, "UPSTASH_REDIS_REST_URL");
  const token = getEnvValue(env, "UPSTASH_REDIS_REST_TOKEN");

  return {
    url,
    token,
    hasConfig: Boolean(url && token)
  };
}

function createNoopRedisMethod(methodName) {
  return async (..._args) => {
    switch (String(methodName)) {
      case "get":
      case "hget":
        return null;
      case "set":
      case "expire":
        return false;
      case "del":
      case "incr":
      case "decr":
      case "hset":
      case "lpush":
      case "zadd":
      case "ltrim":
        return 0;
      case "ttl":
        return -1;
      case "hgetall":
        return {};
      case "lrange":
      case "zrange":
        return [];
      case "ping":
        return "NOOP";
      default:
        return null;
    }
  };
}

function createNoopRedisClient() {
  return new Proxy(
    {
      __isNoopRedis: true,
      __redisAvailable: false
    },
    {
      get(target, prop) {
        if (prop in target) {
          return target[prop];
        }
        return createNoopRedisMethod(String(prop));
      }
    }
  );
}

const noopRedis = createNoopRedisClient();

/* -------------------- CORE CLIENT -------------------- */

export function getRedis(env = {}) {
  const { url, token, hasConfig } = getRedisConfig(env);

  if (!hasConfig) {
    if (!redisInitAttempted) {
      console.error("Upstash Redis environment variables are missing.");
      redisInitAttempted = true;
    }
    return noopRedis;
  }

  const signature = `${url}::${token.slice(0, 12)}`;

  if (redisInstance && redisInitSignature === signature) {
    return redisInstance;
  }

  try {
    redisInstance = new Redis({
      url,
      token
    });
    redisInitSignature = signature;
    redisInitAttempted = true;
    return redisInstance;
  } catch (error) {
    console.error("Upstash Redis initialization failed:", error);
    return noopRedis;
  }
}

export function isRedisAvailable(env = {}) {
  const client = getRedis(env);
  return client && client.__isNoopRedis !== true;
}

export function requireRedis(env = {}) {
  const client = getRedis(env);

  if (!client || client.__isNoopRedis === true) {
    throw new Error("Redis unavailable for required security operation.");
  }

  return client;
}

export function getRedisCapabilities(env = {}) {
  const client = getRedis(env);

  return {
    available: client && client.__isNoopRedis !== true,
    listOps: Boolean(
      client &&
        typeof client.lpush === "function" &&
        typeof client.lrange === "function" &&
        typeof client.ltrim === "function" &&
        typeof client.expire === "function"
    ),
    keyOps: Boolean(
      client &&
        typeof client.get === "function" &&
        typeof client.set === "function" &&
        typeof client.del === "function"
    )
  };
}

/* -------------------- HELPER OPERATIONS -------------------- */

export async function setIfNotExistsWithExpiry(env = {}, key = "", value = "1", ttlSeconds = 60) {
  const redis = requireRedis(env);
  const safeKey = safeString(key, 500);
  const safeValue = safeString(value, 5000);
  const safeTtl = Math.max(1, Math.floor(Number(ttlSeconds) || 1));

  const result = await redis.set(safeKey, safeValue, {
    nx: true,
    ex: safeTtl
  });

  return result === "OK";
}

export async function incrementWithExpiry(env = {}, key = "", ttlSeconds = 60) {
  const redis = requireRedis(env);
  const safeKey = safeString(key, 500);
  const safeTtl = Math.max(1, Math.floor(Number(ttlSeconds) || 1));

  const value = await redis.incr(safeKey);

  // Best-effort expiry set. Not perfectly atomic in REST clients,
  // but still much safer than read-modify-write.
  await redis.expire(safeKey, safeTtl).catch(() => {});

  return Number(value) || 0;
}

export async function appendToRecentList(
  env = {},
  key = "",
  item = "",
  maxItems = 100,
  ttlSeconds = 60
) {
  const redis = requireRedis(env);
  const safeKey = safeString(key, 500);
  const safeMaxItems = Math.max(1, Math.floor(Number(maxItems) || 1));
  const safeTtl = Math.max(1, Math.floor(Number(ttlSeconds) || 1));

  if (
    typeof redis.lpush !== "function" ||
    typeof redis.ltrim !== "function" ||
    typeof redis.expire !== "function"
  ) {
    throw new Error("Redis list operations are unavailable.");
  }

  const serialized =
    typeof item === "string" ? item : JSON.stringify(item);

  await redis.lpush(safeKey, serialized);
  await redis.ltrim(safeKey, 0, safeMaxItems - 1);
  await redis.expire(safeKey, safeTtl);

  return true;
}

export async function getRecentList(env = {}, key = "", limit = 100) {
  const redis = requireRedis(env);
  const safeKey = safeString(key, 500);
  const safeLimit = Math.max(1, Math.floor(Number(limit) || 1));

  if (typeof redis.lrange !== "function") {
    throw new Error("Redis list operations are unavailable.");
  }

  const items = await redis.lrange(safeKey, 0, safeLimit - 1);
  return Array.isArray(items) ? items : [];
}

export async function deleteRedisKey(env = {}, key = "") {
  const redis = requireRedis(env);
  const safeKey = safeString(key, 500);
  return redis.del(safeKey);
}

/* -------------------- LEGACY GLOBAL PROXY -------------------- */

export const redis = new Proxy(
  {},
  {
    get(_target, prop) {
      const client = getRedis();
      const value = client?.[prop];

      if (typeof value === "function") {
        return value.bind(client);
      }

      if (value !== undefined) {
        return value;
      }

      return createNoopRedisMethod(String(prop));
    }
  }
);
