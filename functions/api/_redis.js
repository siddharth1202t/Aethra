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
    { __isNoopRedis: true, __redisAvailable: false },
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
