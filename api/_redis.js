import { Redis } from "@upstash/redis";

let redisInstance = null;

export function getRedis() {
  if (!redisInstance) {
    redisInstance = Redis.fromEnv();
  }

  return redisInstance;
}
