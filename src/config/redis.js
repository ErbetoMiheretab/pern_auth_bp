import Redis from "ioredis";
import RedisMock from "ioredis-mock";
import { redis as redisVars, env } from "./vars.js"; // Assuming this holds your env vars

let redis;

if (process.env.NODE_ENV === "test") {
  // Use the mock client for tests
  redis = new RedisMock();
} else {
  // Use the real ioredis client for dev/production
  redis = new Redis({
    host: redisVars.host || "127.0.0.1",
    port: redisVars.port || 6378,
    password: redisVars.password || undefined,
    maxRetriesPerRequest: 3,
    // ioredis connects automatically, no need for manual .connect()
  });

  redis.on("connect", () => {
    console.log("Redis connected successfully");
  });

  redis.on("error", (err) => {
    console.error("Redis Connection Error:", err);
  });
}

// Graceful shutdown
process.on("SIGTERM", async () => {
  await redis.quit();
});

export default redis;
