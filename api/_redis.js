import { Redis } from "@upstash/redis";

let redisInstance = null;

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

  if (!hasRedisEnv()) {
    throw new Error("Upstash Redis environment variables are missing.");
  }

  redisInstance = Redis.fromEnv();
  return redisInstance;
}

export const redis = new Proxy(
  {},
  {
    get(_target, prop) {
      const client = getRedis();
      const value = client[prop];

      if (typeof value === "function") {
        return value.bind(client);
      }

      return value;
    }
  }
);
