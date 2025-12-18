import Redis from 'ioredis';
import RedisMock from 'ioredis-mock';
import { redis as redisVars } from './vars.js'; // Assuming this holds your env vars

let redis;

if (process.env.NODE_ENV === 'test') {
  // Use the mock client for tests
  redis = new RedisMock();
} else {
  // Use the real ioredis client for dev/production
  redis = new Redis({
    host: redisVars.host || '127.0.0.1',
    port: redisVars.port || 6379,
    password: redisVars.password || undefined,
    // ioredis connects automatically, no need for manual .connect()
  });

  redis.on('error', (err) => {
    console.error("Redis Connection Error:", err);
  });

  redis.on('connect', () => {
    console.log("🚀 Redis connected successfully");
  });
}

export default redis;