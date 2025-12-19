import { jest } from "@jest/globals";
import jwtLib from "jsonwebtoken";

// 1. MOCK DEPENDENCIES
// We mock these BEFORE importing the actual file so the mocks are used.
const mockRedis = {
  get: jest.fn(),
  setEx: jest.fn(),
  exists: jest.fn(),
  incr: jest.fn(),
  expire: jest.fn(),
  on: jest.fn(), // for error listeners
};

// Use unstable_mockModule for ESM support
jest.unstable_mockModule("../../src/config/redis.js", () => ({
  default: mockRedis,
}));

jest.unstable_mockModule("../../src/config/vars.js", () => ({
  env: "test",
  jwt: {
    accessSecret: "test-access-secret",
    refreshSecret: "test-refresh-secret",
    accessExpire: "15m",
    refreshExpire: "7d",
  },
}));

// 2. IMPORT FILE TO TEST
// Dynamic import is required after defining mocks
const {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  tokenStore,
  getUserCurrentVersion,
} = await import("../../src/utils/tokens.js");

describe("TokenStore Utility", () => {
  const userId = "user-123";
  const secrets = {
    access: "test-access-secret",
    refresh: "test-refresh-secret",
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ----------------------------------------------------------------
  // SECTION 1: JWT GENERATION & VERIFICATION
  // ----------------------------------------------------------------
  describe("JWT Helpers", () => {
    it("should generate an Access Token with user version 0 if Redis returns null", async () => {
      mockRedis.get.mockResolvedValue(null); // Simulate no version set

      const token = await generateAccessToken({ sub: userId });
      const decoded = jwtLib.verify(token, secrets.access);

      expect(decoded.sub).toBe(userId);
      expect(decoded.v).toBe(0); // Default version
    });

    it("should generate a Refresh Token with JTI and version", async () => {
      mockRedis.get.mockResolvedValue("5"); // Simulate version 5 in Redis

      const { token, jti } = await generateRefreshToken({ sub: userId });
      const decoded = jwtLib.verify(token, secrets.refresh);

      expect(decoded.jti).toBe(jti);
      expect(decoded.v).toBe(5);
      expect(jti).toBeDefined();
    });

    it("should return null when verifying an invalid token", () => {
      const result = verifyToken("invalid.token.string", secrets.access);
      expect(result).toBeNull();
    });

    it("should return payload when verifying a valid token", () => {
      const token = jwtLib.sign({ foo: "bar" }, secrets.access);
      const result = verifyToken(token, secrets.access);
      expect(result.foo).toBe("bar");
    });
  });

  // ----------------------------------------------------------------
  // SECTION 2: TOKEN REVOCATION (BLACKLIST)
  // ----------------------------------------------------------------
  describe("tokenStore.isRevoked", () => {
    it("should return false if JTI is invalid", async () => {
      expect(await tokenStore.isRevoked(null)).toBe(false);
      expect(await tokenStore.isRevoked("")).toBe(false);
    });

    it("should return true if token exists in Redis", async () => {
      mockRedis.exists.mockResolvedValue(1); // Redis returns 1 for exists
      const isRevoked = await tokenStore.isRevoked("valid-uuid");
      expect(isRevoked).toBe(true);
      expect(mockRedis.exists).toHaveBeenCalledWith("revoked:jti:valid-uuid");
    });

    it("should return false if token does not exist in Redis", async () => {
      mockRedis.exists.mockResolvedValue(0);
      const isRevoked = await tokenStore.isRevoked("valid-uuid");
      expect(isRevoked).toBe(false);
    });
  });

  describe("tokenStore.revoke", () => {
    it("should store JTI in Redis with correct TTL", async () => {
      const jti = "test-jti";
      const nowSeconds = Math.floor(Date.now() / 1000);
      // Create a token that expires in 1 hour (3600 seconds)
      const decodedToken = { exp: nowSeconds + 3600 };

      await tokenStore.revoke(jti, decodedToken);

      expect(mockRedis.setEx).toHaveBeenCalledWith(
        `revoked:jti:${jti}`,
        expect.any(Number), // We check logic below, just ensure it's called
        "1"
      );

      // Verify TTL is roughly 3600 (allowing for minimal execution time diff)
      const ttlArg = mockRedis.setEx.mock.calls[0][1];
      expect(ttlArg).toBeLessThanOrEqual(3600);
      expect(ttlArg).toBeGreaterThan(3590);
    });

    it("should NOT revoke if token is already expired", async () => {
      const jti = "test-jti";
      const nowSeconds = Math.floor(Date.now() / 1000);
      const decodedToken = { exp: nowSeconds - 100 }; // Expired 100s ago

      await tokenStore.revoke(jti, decodedToken);

      expect(mockRedis.setEx).not.toHaveBeenCalled();
    });
  });

  // ----------------------------------------------------------------
  // SECTION 3: USER VERSIONING (LOGOUT ALL)
  // ----------------------------------------------------------------
  describe("tokenStore.revokeAllForUser", () => {
    it("should increment user version in Redis atomically", async () => {
      mockRedis.incr.mockResolvedValue(2); // Simulate version going from 1 -> 2

      const newVersion = await tokenStore.revokeAllForUser(userId);

      expect(mockRedis.incr).toHaveBeenCalledWith(`user:rev:version:${userId}`);
      expect(mockRedis.expire).toHaveBeenCalledWith(
        `user:rev:version:${userId}`,
        expect.any(Number)
      );
      expect(newVersion).toBe(2);
    });

    it("should throw error if userId is invalid", async () => {
      await expect(tokenStore.revokeAllForUser(null)).rejects.toThrow();
    });
  });

  describe("tokenStore.isVersionValid", () => {
    it("should return false if token has NO version (Strict Mode)", async () => {
      // Logic: Old tokens without 'v' are considered invalid
      const result = await tokenStore.isVersionValid({ sub: userId });
      expect(result).toBe(false);
    });

    it("should return true if token version matches Redis version", async () => {
      mockRedis.get.mockResolvedValue("5");
      const result = await tokenStore.isVersionValid({ sub: userId, v: 5 });
      expect(result).toBe(true);
    });

    it("should return false if token version is OLDER than Redis version", async () => {
      mockRedis.get.mockResolvedValue("6"); // User logged out (revoked all)
      const result = await tokenStore.isVersionValid({ sub: userId, v: 5 });
      expect(result).toBe(false);
    });

    it("should return true if Redis is empty (0) and Token is 0", async () => {
      mockRedis.get.mockResolvedValue(null); // Effectively 0
      const result = await tokenStore.isVersionValid({ sub: userId, v: 0 });
      expect(result).toBe(true);
    });
  });

  // ----------------------------------------------------------------
  // SECTION 4: EDGE CASES & ERROR HANDLING
  // ----------------------------------------------------------------
  describe("Robustness", () => {
    it("getUserCurrentVersion should return 0 (safe default) if Redis fails", async () => {
      mockRedis.get.mockRejectedValue(new Error("Redis connection lost"));

      // Should not throw, but return 0
      const version = await getUserCurrentVersion(userId);
      expect(version).toBe(0);
    });

    it("isRevoked should return false (fail open) if Redis fails", async () => {
      mockRedis.exists.mockRejectedValue(new Error("Redis connection lost"));

      const isRevoked = await tokenStore.isRevoked("some-jti");
      expect(isRevoked).toBe(false);
    });
  });
});
