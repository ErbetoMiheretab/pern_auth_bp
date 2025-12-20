import crypto from "crypto";
import jwtLib from "jsonwebtoken";
import redisClient from "../config/redis.js";
import { jwt as jwtConfig, env } from "../config/vars.js";

const JWT_ALGO = "HS256";

// ---------------- COOKIES ----------------
export const cookieConfig = {
  httpOnly: true,
  secure: env === "production",
  sameSite: "strict", // Note: Ensure this doesn't block OAuth/Email redirects
  path: "/",
};

// ---------------- INPUT VALIDATION ----------------
const isValidPayload = (payload) =>
  payload && typeof payload === "object" && !Array.isArray(payload);

const isValidJTI = (jti) => typeof jti === "string" && jti.length > 0;

const isValidUserId = (userId) =>
  (typeof userId === "string" || typeof userId === "number") && userId;

// ---------------- TTL PARSING ----------------
// (Kept your logic, it was excellent)
const parseMaxTTL = (expire) => {
  if (typeof expire === "number") return expire > 0 ? expire : 0;
  if (typeof expire !== "string")
    throw new Error("JWT expire must be string or number");
  const match = expire.match(/^(\d+)([smhd])$/);
  if (!match) throw new Error(`Invalid JWT expire format: "${expire}"`);
  const units = { s: 1, m: 60, h: 3600, d: 86400 };
  return parseInt(match[1], 10) * units[match[2]];
};

const MAX_REFRESH_TTL = parseMaxTTL(jwtConfig.refreshExpire);

// ---------------- USER TOKEN VERSION ----------------
const getUserVersionKey = (userId) => `user:rev:version:${userId}`;

export const getUserCurrentVersion = async (userId) => {
  if (!isValidUserId(userId)) return 0;
  try {
    const key = getUserVersionKey(userId);
    const version = await redisClient.get(key);
    return version ? parseInt(version, 10) : 0;
  } catch (err) {
    console.error("Redis error (getUserCurrentVersion):", err.message);
    // Return 0 so we don't break login flow, but this might block
    // authenticated requests if the token has v=1. Fail-closed is safer.
    return 0;
  }
};

const attachUserVersionToPayload = async (payload) => {
  // Normalize User ID: Standard JWT uses 'sub', but fallback to 'userId' or 'id'
  const userId = payload.sub || payload.userId || payload.id;

  if (!userId) {
    // If we can't identify the user, we can't version them.
    // In strict mode, you might want to throw an error here.
    return payload;
  }

  const version = await getUserCurrentVersion(userId);
  // We ensure 'sub' is present for consistency
  return { ...payload, sub: userId, v: version };
};

// ---------------- JWT HELPERS ----------------
export const generateAccessToken = async (payload) => {
  if (!isValidPayload(payload)) throw new Error("Invalid payload");

  const payloadWithVersion = await attachUserVersionToPayload(payload);

  return jwtLib.sign(payloadWithVersion, jwtConfig.accessSecret, {
    expiresIn: jwtConfig.accessExpire,
    algorithm: JWT_ALGO,
  });
};

export const generateRefreshToken = async (payload) => {
  if (!isValidPayload(payload)) throw new Error("Invalid payload");

  const jti = crypto.randomUUID();
  // Ensure version is attached to refresh token too
  const payloadWithVersion = await attachUserVersionToPayload({
    ...payload,
    jti,
  });

  const token = jwtLib.sign(payloadWithVersion, jwtConfig.refreshSecret, {
    expiresIn: jwtConfig.refreshExpire,
    algorithm: JWT_ALGO,
  });

  return { token, jti };
};

export const verifyToken = (token, secret) => {
  if (!token || typeof token !== "string") return null;
  try {
    return jwtLib.verify(token, secret, { algorithms: [JWT_ALGO] });
  } catch (err) {
    if (env !== "production") console.warn("JWT verify:", err.message);
    return null;
  }
};

// ---------------- TOKEN STORE ----------------
export const tokenStore = {
  // 1. Check Blacklist (Specific Token)
  async isRevoked(jti) {
    if (!isValidJTI(jti)) return false;
    try {
      // Use Exists (returns 1 or 0)
      const exists = await redisClient.exists(`revoked:jti:${jti}`);
      return exists === 1;
    } catch (err) {
      console.error("Redis error (isRevoked):", err.message);
      return false; // Fail open (allow access) if Redis dies, or true to block.
    }
  },

  // 2. Blacklist a specific token
  async revoke(jti, decodedToken) {
    if (!isValidJTI(jti)) return;

    // Optimization: Calculate remaining TTL
    let ttl = MAX_REFRESH_TTL;
    if (decodedToken?.exp) {
      const now = Math.floor(Date.now() / 1000);
      const remaining = decodedToken.exp - now;
      if (remaining <= 0) return; // Already expired
      if (remaining < ttl) ttl = remaining;
    }

    try {
      await redisClient.setex(`revoked:jti:${jti}`, ttl, "1");
    } catch (err) {
      console.error("Redis error (revoke):", err.message);
    }
  },

  // 3. GLOBAL LOGOUT: Increment User Version
  async revokeAllForUser(userId) {
    if (!isValidUserId(userId)) throw new Error("Invalid userId");

    const key = getUserVersionKey(userId);
    const ONE_YEAR_SECONDS = 31536000;

    try {
      // ATOMIC INCREMENT
      // If key doesn't exist, INCR sets it to 1.
      // If it exists (e.g., 5), it becomes 6.
      const newVersion = await redisClient.incr(key);

      // Reset the expiration so the version key doesn't expire
      // while the user is still active (garbage collection)
      await redisClient.expire(key, ONE_YEAR_SECONDS);

      return newVersion;
    } catch (err) {
      console.error("Redis error (revokeAllForUser):", err.message);
      throw new Error("Failed to revoke user sessions");
    }
  },

  // 4. Validate Version
  async isVersionValid(decodedToken) {
    // Normalize User ID
    const userId =
      decodedToken?.sub || decodedToken?.userId || decodedToken?.id;
    if (!userId) return false;

    // STRICT CHECK: If token has no version, and we are using versioning,
    // it's an old or invalid token.
    if (decodedToken.v === undefined) {
      // CHANGE THIS to 'return true' only if you are currently migrating
      // and have old valid tokens in the wild.
      return false;
    }

    const currentVersion = await getUserCurrentVersion(userId);

    // The token version must match the Redis version exactly.
    // If Redis is 0 (first login) and Token is 0, valid.
    // If Redis is 1 (logout happened) and Token is 0, invalid.
    return decodedToken.v === currentVersion;
  },
};
