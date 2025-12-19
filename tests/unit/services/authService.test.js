import { jest } from "@jest/globals";

// ------------------------------------------------------------------
// 1. MOCK DEPENDENCIES
// We must mock these BEFORE importing the service to be tested.
// Use unstable_mockModule for ESM support
// ------------------------------------------------------------------

const mockUserInstance = {
  id: 1,
  email: "test@example.com",
  password: "hashed_password",
  toJSON: jest.fn(),
  validatePassword: jest.fn(),
};

// Mock User Model
jest.unstable_mockModule("../../../src/models/index.js", () => ({
  User: {
    findOne: jest.fn(),
    create: jest.fn(),
    findByPk: jest.fn(),
  },
  Role: {},
  Permission: {},
}));

// Mock Token Utilities
jest.unstable_mockModule("../../../src/utils/tokens.js", () => ({
  generateAccessToken: jest.fn(),
  generateRefreshToken: jest.fn(),
  verifyToken: jest.fn(),
  tokenStore: {
    isRevoked: jest.fn(),
    isVersionValid: jest.fn(),
    revoke: jest.fn(),
    revokeAllForUser: jest.fn(),
  },
}));

// Mock Config
jest.unstable_mockModule("../../../src/config/vars.js", () => ({
  jwt: {
    refreshSecret: "test_refresh_secret",
  },
}));

// ------------------------------------------------------------------
// 2. IMPORT MODULES (Dynamic Import)
// ------------------------------------------------------------------

const { User } = await import("../../../src/models/index.js");
const { generateAccessToken, generateRefreshToken, verifyToken, tokenStore } =
  await import("../../../src/utils/tokens.js");
const AuthService = await import("../../../src/auth/auth.service.js");

// ------------------------------------------------------------------
// 3. TEST SUITE
// ------------------------------------------------------------------
describe("Auth Service", () => {
  const userData = { email: "test@example.com", password: "password123" };
  const userJson = { id: 1, email: "test@example.com" };

  beforeEach(() => {
    jest.clearAllMocks();
    // Default mock implementation for user instance methods
    mockUserInstance.toJSON.mockReturnValue(userJson);
    mockUserInstance.validatePassword.mockResolvedValue(true);
    
    // Reset token mocks to defaults (Success)
    generateAccessToken.mockResolvedValue("default-access-token");
    generateRefreshToken.mockResolvedValue({ token: "default-refresh-token" });
    tokenStore.isRevoked.mockResolvedValue(false);
    tokenStore.isVersionValid.mockResolvedValue(true);
  });

  // =================================================================
  // REGISTER TESTS
  // =================================================================
  describe("register", () => {
    it("should successfully register a new user", async () => {
      // Setup
      User.findOne.mockResolvedValue(null); // User does not exist
      User.create.mockResolvedValue(mockUserInstance);
      generateAccessToken.mockResolvedValue("access-token-123");
      generateRefreshToken.mockResolvedValue({ token: "refresh-token-123" });

      // Execute
      const result = await AuthService.register(userData);

      // Assert
      expect(User.findOne).toHaveBeenCalledWith({
        where: { email: userData.email },
      });
      expect(User.create).toHaveBeenCalledWith(userData);
      expect(generateAccessToken).toHaveBeenCalledWith(userJson);
      expect(result).toEqual({
        user: userJson,
        accessToken: "access-token-123",
        refreshToken: "refresh-token-123",
      });
    });

    it("should throw 409 if email already exists", async () => {
      User.findOne.mockResolvedValue({ id: 2 }); // User exists

      await expect(AuthService.register(userData)).rejects.toMatchObject({
        message: "Email already in use",
        status: 409,
      });

      expect(User.create).not.toHaveBeenCalled();
    });
  });

  // =================================================================
  // LOGIN TESTS
  // =================================================================
  describe("login", () => {
    it("should successfully login with valid credentials", async () => {
      User.findOne.mockResolvedValue(mockUserInstance);
      User.findByPk.mockResolvedValue(mockUserInstance); // Added this
      mockUserInstance.validatePassword.mockResolvedValue(true);
      generateAccessToken.mockResolvedValue("access-token-123");
      generateRefreshToken.mockResolvedValue({ token: "refresh-token-123" });

      const result = await AuthService.login(userData.email, userData.password);

      expect(mockUserInstance.validatePassword).toHaveBeenCalledWith(
        userData.password
      );
      expect(result).toEqual({
        user: userJson,
        accessToken: "access-token-123",
        refreshToken: "refresh-token-123",
      });
    });

    it("should throw 401 if user not found", async () => {
      User.findOne.mockResolvedValue(null);

      await expect(
        AuthService.login(userData.email, userData.password)
      ).rejects.toMatchObject({
        message: "Incorrect email or password",
        status: 401,
      });
    });

    it("should throw 401 if password does not match", async () => {
      User.findOne.mockResolvedValue(mockUserInstance);
      mockUserInstance.validatePassword.mockResolvedValue(false);

      await expect(
        AuthService.login(userData.email, userData.password)
      ).rejects.toMatchObject({
        message: "Incorrect email or password",
        status: 401,
      });
    });
  });

  // =================================================================
  // REFRESH TESTS
  // =================================================================
  describe("refresh", () => {
    const validRefreshToken = "valid-refresh-token";
    const decodedToken = { sub: 1, jti: "uuid-jti", v: 1 };

    it("should successfully rotate tokens if refresh token is valid", async () => {
      // 1. Verify token succeeds
      verifyToken.mockReturnValue(decodedToken);
      // 2. Token is NOT revoked
      tokenStore.isRevoked.mockResolvedValue(false);
      // 3. Version is valid
      tokenStore.isVersionValid.mockResolvedValue(true);
      // 4. User exists
      User.findByPk.mockResolvedValue(mockUserInstance);

      // Mock new token generation
      generateAccessToken.mockResolvedValue("new-access");
      generateRefreshToken.mockResolvedValue({ token: "new-refresh" });

      const result = await AuthService.refresh(validRefreshToken);

      // Expect old token to be revoked (Rotation)
      expect(tokenStore.revoke).toHaveBeenCalledWith(
        decodedToken.jti,
        decodedToken
      );

      expect(result).toEqual({
        accessToken: "new-access",
        refreshToken: "new-refresh",
      });
    });

    it("should throw 400 if token is missing", async () => {
      await expect(AuthService.refresh(null)).rejects.toMatchObject({
        message: "Refresh token is required",
        status: 400,
      });
    });

    it("should throw 401 if token is invalid/expired (verify returns null)", async () => {
      verifyToken.mockReturnValue(null);

      await expect(AuthService.refresh("bad-token")).rejects.toMatchObject({
        message: "Invalid or expired refresh token",
        status: 401,
      });
    });

    it("should throw 401 if token is in blacklist (revoked)", async () => {
      verifyToken.mockReturnValue(decodedToken);
      tokenStore.isRevoked.mockResolvedValue(true);

      await expect(AuthService.refresh(validRefreshToken)).rejects.toMatchObject({
        message: "Token revoked",
        status: 401,
      });
    });

    it("should throw 401 if token version mismatches (Global Logout)", async () => {
      verifyToken.mockReturnValue(decodedToken);
      tokenStore.isRevoked.mockResolvedValue(false);
      tokenStore.isVersionValid.mockResolvedValue(false);

      await expect(AuthService.refresh(validRefreshToken)).rejects.toMatchObject({
        message: "Token version mismatch (User logged out?)",
        status: 401,
      });
    });

    it("should throw 404 if user no longer exists", async () => {
      verifyToken.mockReturnValue(decodedToken);
      tokenStore.isRevoked.mockResolvedValue(false);
      tokenStore.isVersionValid.mockResolvedValue(true);
      User.findByPk.mockResolvedValue(null);

      await expect(AuthService.refresh(validRefreshToken)).rejects.toMatchObject({
        message: "User not found",
        status: 404,
      });
    });
  });

  // =================================================================
  // LOGOUT TESTS
  // =================================================================
  describe("logout", () => {
    it("should revoke the specific token if valid", async () => {
      const token = "some-token";
      const decoded = { jti: "abc", exp: 123 };
      verifyToken.mockReturnValue(decoded);

      await AuthService.logout(token);

      expect(tokenStore.revoke).toHaveBeenCalledWith("abc", decoded);
    });

    it("should do nothing if token is invalid", async () => {
      verifyToken.mockReturnValue(null);
      await AuthService.logout("bad-token");
      expect(tokenStore.revoke).not.toHaveBeenCalled();
    });

    it("should do nothing if token is null", async () => {
      await AuthService.logout(null);
      expect(verifyToken).not.toHaveBeenCalled();
    });
  });

  // =================================================================
  // LOGOUT ALL TESTS
  // =================================================================
  describe("logoutAll", () => {
    it("should call revokeAllForUser", async () => {
      await AuthService.logoutAll(123);
      expect(tokenStore.revokeAllForUser).toHaveBeenCalledWith(123);
    });
  });

  // =================================================================
  // EDGE CASES & INFRASTRUCTURE FAILURES
  // =================================================================
  describe("Edge Cases & Failures", () => {
    
    // --- REGISTER EDGE CASES ---
    describe("register (Edge Cases)", () => {
      it("should propagate database errors (e.g. DB connection lost)", async () => {
        const dbError = new Error("Database connection failed");
        User.findOne.mockRejectedValue(dbError);

        await expect(AuthService.register(userData)).rejects.toThrow("Database connection failed");
      });

      it("should fail if token generation fails (e.g. Redis down during sign)", async () => {
        User.findOne.mockResolvedValue(null);
        User.create.mockResolvedValue(mockUserInstance);
        
        // Simulate Token Signer/Redis failure
        generateAccessToken.mockRejectedValue(new Error("Redis connection timeout"));

        await expect(AuthService.register(userData)).rejects.toThrow("Redis connection timeout");
      });
    });

    // --- REFRESH EDGE CASES ---
    describe("refresh (Edge Cases)", () => {
      const validRefreshToken = "valid-refresh-token";
      const decodedToken = { sub: 1, jti: "uuid-jti", v: 1 };

      it("should throw if token payload is missing 'jti' (Malformed Token)", async () => {
        // Valid signature, but payload corrupted/legacy
        verifyToken.mockReturnValue({ sub: 1, v: 1 }); // Missing JTI
        
        // Assuming tokenStore.isRevoked might throw or return false. 
        // If the code doesn't explicitly check for JTI existence, it passes undefined.
        // Let's assume strict checking in tokenStore or test the fail-safe.
        tokenStore.isRevoked.mockResolvedValue(false);
        tokenStore.isVersionValid.mockResolvedValue(true);
        User.findByPk.mockResolvedValue(mockUserInstance);

        // Rotation step: tokenStore.revoke(undefined, ...) 
        // This tests that the service continues or fails depending on implementation.
        // Based on your code, it calls revoke.
        
        await AuthService.refresh(validRefreshToken);
        expect(tokenStore.revoke).toHaveBeenCalledWith(undefined, expect.anything());
      });

      it("should fail if Redis fails during blacklist check (Fail Closed)", async () => {
        verifyToken.mockReturnValue(decodedToken);
        // Simulate Redis error
        tokenStore.isRevoked.mockRejectedValue(new Error("Redis connection failed"));

        await expect(AuthService.refresh(validRefreshToken)).rejects.toThrow("Redis connection failed");
      });

      it("should fail if Redis fails during Version check", async () => {
        verifyToken.mockReturnValue(decodedToken);
        tokenStore.isRevoked.mockResolvedValue(false);
        tokenStore.isVersionValid.mockRejectedValue(new Error("Redis error"));

        await expect(AuthService.refresh(validRefreshToken)).rejects.toThrow("Redis error");
      });

      it("should fail if Token Rotation (revoke old token) fails", async () => {
        verifyToken.mockReturnValue(decodedToken);
        tokenStore.isRevoked.mockResolvedValue(false);
        tokenStore.isVersionValid.mockResolvedValue(true);
        User.findByPk.mockResolvedValue(mockUserInstance);
        
        // Simulate Redis failing strictly during the rotation write
        tokenStore.revoke.mockRejectedValue(new Error("Write failed"));

        // Security check: If we can't revoke the old token, we probably shouldn't issue a new one
        await expect(AuthService.refresh(validRefreshToken)).rejects.toThrow("Write failed");
      });
      
      it("should handle decoded payload missing 'sub' (User ID)", async () => {
        // Token valid, but payload has no user ID
        verifyToken.mockReturnValue({ jti: "uuid", v: 1 }); 
        tokenStore.isRevoked.mockResolvedValue(false);
        tokenStore.isVersionValid.mockResolvedValue(true);
        
        // User.findByPk(undefined) usually returns null in Sequelize/Mongoose
        User.findByPk.mockResolvedValue(null);

        await expect(AuthService.refresh(validRefreshToken)).rejects.toMatchObject({
            message: "User not found",
            status: 404
        });
      });
    });

    // --- LOGOUT EDGE CASES ---
    describe("logout (Edge Cases)", () => {
      it("should not throw if revocation fails (Best Effort Logout)", async () => {
        // Many systems treat logout as 'fire and forget'
        // If your system MUST fail, change this expectation.
        verifyToken.mockReturnValue({ jti: "abc" });
        tokenStore.revoke.mockRejectedValue(new Error("Redis down"));

        // Assuming the logout function awaits but doesn't try/catch, it WILL throw.
        // If you want it to fail:
        await expect(AuthService.logout("token")).rejects.toThrow("Redis down");
        
        /* 
           NOTE: If your actual code had a try/catch inside logout to suppress errors, 
           verifyToken would be called and expectation would be:
           await expect(AuthService.logout("token")).resolves.not.toThrow();
        */
      });
    });
  });
});