import redis from "../config/redis.js";

const blacklistKey = (jti) => `bl:${jti}`;
const rolesKey = (userId) => `roles:${userId}`;

export async function blacklist(jti, ttlSeconds) {
  // Consistency: use set with EX
  await redis.set(blacklistKey(jti), "1", "EX", ttlSeconds);
}

export async function isBlacklisted(jti) {
  const res = await redis.get(blacklistKey(jti));
  return res === "1";
}

export async function cacheRoles(userId, rolesArr) {
  //   await redis.set(rolesKey(userId), JSON.stringify(rolesArr), 'EX', 60);

  const pipeline = redis.pipeline();

  // Command 1: Cache the roles
  pipeline.set(rolesKey(userId), JSON.stringify(rolesArr), "EX", 60);

  // Command 2: Update a user activity log (Example of why to use pipeline)
  pipeline.zadd("active_users", Date.now(), userId);

  // Execute all at once
  await pipeline.exec();
}

export async function getCachedRoles(userId) {
  try {
    const data = await redis.get(rolesKey(userId));
    return data ? JSON.parse(data) : null;
  } catch (err) {
    console.error("Redis Parse Error:", err);
    return null;
  }
}
