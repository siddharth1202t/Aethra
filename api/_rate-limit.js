const apiLimiter = new Map();

const MAX_REQUESTS = 60;
const WINDOW_MS = 60 * 1000;

export function checkApiRateLimit(ip) {

  const now = Date.now();
  const record = apiLimiter.get(ip) || {
    count: 0,
    start: now
  };

  if (now - record.start > WINDOW_MS) {
    record.count = 0;
    record.start = now;
  }

  record.count++;

  apiLimiter.set(ip, record);

  if (record.count > MAX_REQUESTS) {
    return false;
  }

  return true;
}
