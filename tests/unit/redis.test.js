import { jest } from "@jest/globals";

import redis from "../../src/config/redis.js";

import {
  blacklist,
  isBlacklisted,
  cacheRoles,
  getCachedRoles,
} from "../../src/utils/redis.js";

describe("Redis Utils", () => {
  // Use unique identifiers to avoid collisions with other developers/tests
  const testJti = `test-jti-${Date.now()}`;
  const testUserId = `test-user-${Date.now()}`;

  beforeEach(async () => {
    // If using ioredis-mock, this clears all data between tests
    if (redis.flushall) await redis.flushall();
  });
  afterAll(async () => {
    // Cleanup specific keys to leave the DB clean
    await redis.quit();
  });

  test("blacklist and isBlacklisted", async () => {
    await blacklist(testJti, 1); // Shorter TTL for faster test
    expect(await isBlacklisted(testJti)).toBe(true);

    // Wait for expiration
    await new Promise((r) => setTimeout(r, 1200));
    expect(await isBlacklisted(testJti)).toBe(false);
  });

  test("cacheRoles and getCachedRoles", async () => {
    const roles = ["admin", "editor"];
    await cacheRoles(testUserId, roles);
    const cached = await getCachedRoles(testUserId);
    expect(cached).toEqual(roles);
  });

  test("getCachedRoles returns null if user is not in cache", async () => {
    const result = await getCachedRoles("non-existent-user");
    expect(result).toBeNull();
  });

  test("isBlacklisted returns false for non-blacklisted JTI", async () => {
    const result = await isBlacklisted("fresh-token-jti");
    expect(result).toBe(false);
  });
  test("cacheRoles handles an empty roles array", async () => {
    const userId = "empty-user";
    const roles = [];

    await cacheRoles(userId, roles);
    const cached = await getCachedRoles(userId);

    expect(cached).toEqual([]);
  });
  test("getCachedRoles handles corrupted/non-JSON data gracefully", async () => {
    const userId = "corrupted-user";
    // Manually set a value that isn't JSON
    await redis.set(`roles:${userId}`, "not-valid-json");

    // Spy on console.error and mock it to do nothing
    const consoleSpy = jest
      .spyOn(console, "error")
      .mockImplementation(() => {});

    const result = await getCachedRoles(userId);
    expect(result).toBeNull(); // It should return null instead of crashing

    expect(result).toBeNull();
    expect(consoleSpy).toHaveBeenCalled(); // Ensure the error WAS caught

    // Clean up the spy
    consoleSpy.mockRestore();
  });

  test("blacklist handles zero TTL", async () => {
    const jti = "instant-expire";
    await blacklist(jti, 0);

    const result = await isBlacklisted(jti);
    // Depending on Redis speed, this usually returns false immediately
    expect(result).toBe(false);
  });
});
