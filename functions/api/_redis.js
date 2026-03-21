import { Redis } from "@upstash/redis";

let redisInstance = null;
let redisInitAttempted = false;

function safeString(value, maxLength = 500) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

function hasRedisEnv() {
  const url = safeString(process.env.UPSTASH_REDIS_REST_URL || "", 2000);
  const token = safeString(process.env.UPSTASH_REDIS_REST_TOKEN || "", 2000);
  return Boolean(url && token);
}

export function getRedis() {
  if (redisInstance) {
    return redisInstance;
  }

  if (redisInitAttempted) {
    return null;
  }

  redisInitAttempted = true;

  if (!hasRedisEnv()) {
    console.error("Upstash Redis environment variables are missing.");
    return null;
  }

  try {
    redisInstance = Redis.fromEnv();
    return redisInstance;
  } catch (error) {
    console.error("Upstash Redis initialization failed:", error);
    return null;
  }
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
      default:
        return null;
    }
  };
}

export const redis = new Proxy(
  {},
  {
    get(_target, prop) {
      const client = getRedis();

      if (!client) {
        return createNoopRedisMethod(String(prop));
      }

      const value = client[prop];

      if (typeof value === "function") {
        return value.bind(client);
      }

      return value;
    }
  }
);
