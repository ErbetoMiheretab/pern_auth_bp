import { jest } from "@jest/globals";

// ------------------------------------------------------------------
// ------------------------------------------------------------------
// 1. MOCK DEPENDENCIES
// ------------------------------------------------------------------

// Mock the Service (ESM requires unstable_mockModule for full mock hoisting support in some envs)
jest.unstable_mockModule("../../src/auth/auth.service.js", () => ({
  register: jest.fn(),
  login: jest.fn(),
  refresh: jest.fn(),
  logout: jest.fn(),
  logoutAll: jest.fn(),
}));

// Mock the Utils (cookieConfig)
const mockCookieConfig = {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
};
jest.unstable_mockModule("../../src/utils/tokens.js", () => ({
  cookieConfig: mockCookieConfig,
}));

// ------------------------------------------------------------------
// 2. IMPORT MODULES
// ------------------------------------------------------------------
const authService = await import("../../src/auth/auth.service.js");
const authController = await import("../../src/auth/auth.controller.js");
const { cookieConfig } = await import("../../src/utils/tokens.js");

// ------------------------------------------------------------------
// 3. SETUP & HELPERS
// ------------------------------------------------------------------
describe("Auth Controller", () => {
  let req, res, next;

  // Reset mocks before each test
  beforeEach(() => {
    req = {
      body: {},
      cookies: {},
      user: {},
    };
    res = {
      cookie: jest.fn(),
      clearCookie: jest.fn(),
      status: jest.fn().mockReturnThis(), // Allows chaining .status(201).json(...)
      json: jest.fn(),
      end: jest.fn(),
    };
    next = jest.fn();
    jest.clearAllMocks();
  });

  const mockUser = { id: 1, email: "test@test.com" };
  const mockTokens = {
    accessToken: "access-123",
    refreshToken: "refresh-123",
  };

  // =================================================================
  // REGISTER TESTS
  // =================================================================
  describe("register", () => {
    it("should register user, set cookie, and return 201", async () => {
      req.body = { email: "new@test.com", password: "pw" };
      
      authService.register.mockResolvedValue({
        user: mockUser,
        ...mockTokens,
      });

      await authController.register(req, res, next);

      // Service Check
      expect(authService.register).toHaveBeenCalledWith(req.body);

      // Cookie Check
      expect(res.cookie).toHaveBeenCalledWith(
        "refreshToken",
        mockTokens.refreshToken,
        cookieConfig
      );

      // Response Check
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({
        user: mockUser,
        accessToken: mockTokens.accessToken,
      });
    });

    it("should pass errors to next()", async () => {
      const error = new Error("Email taken");
      authService.register.mockRejectedValue(error);

      await authController.register(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
    });
  });

  // =================================================================
  // LOGIN TESTS
  // =================================================================
  describe("login", () => {
    it("should login user, set cookie, and return JSON", async () => {
      req.body = { email: "test@test.com", password: "pw" };

      authService.login.mockResolvedValue({
        user: mockUser,
        ...mockTokens,
      });

      await authController.login(req, res, next);

      expect(authService.login).toHaveBeenCalledWith(
        req.body.email,
        req.body.password
      );

      expect(res.cookie).toHaveBeenCalledWith(
        "refreshToken",
        mockTokens.refreshToken,
        cookieConfig
      );

      expect(res.json).toHaveBeenCalledWith({
        user: mockUser,
        accessToken: mockTokens.accessToken,
      });
    });

    it("should pass errors to next()", async () => {
      const error = new Error("Invalid credentials");
      authService.login.mockRejectedValue(error);

      await authController.login(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
    });
  });

  // =================================================================
  // REFRESH TESTS
  // =================================================================
  describe("refresh", () => {
    it("should refresh using cookie token and rotate cookie", async () => {
      req.cookies.refreshToken = "old-refresh-token";
      
      authService.refresh.mockResolvedValue({
        accessToken: "new-access",
        refreshToken: "new-refresh",
      });

      await authController.refresh(req, res, next);

      expect(authService.refresh).toHaveBeenCalledWith("old-refresh-token");
      
      // Should set the NEW refresh token
      expect(res.cookie).toHaveBeenCalledWith(
        "refreshToken",
        "new-refresh",
        cookieConfig
      );

      expect(res.json).toHaveBeenCalledWith({
        accessToken: "new-access",
      });
    });

    it("should fallback to body token if cookie is missing", async () => {
      req.cookies = {}; // No cookie
      req.body.refreshToken = "body-refresh-token";

      authService.refresh.mockResolvedValue({
        accessToken: "new-access",
        refreshToken: "new-refresh",
      });

      await authController.refresh(req, res, next);

      expect(authService.refresh).toHaveBeenCalledWith("body-refresh-token");
    });

    it("should pass errors to next()", async () => {
      authService.refresh.mockRejectedValue(new Error("Invalid token"));
      await authController.refresh(req, res, next);
      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });
  });

  // =================================================================
  // LOGOUT TESTS
  // =================================================================
  describe("logout", () => {
    it("should call service logout, clear cookie, and return 204", async () => {
      req.cookies.refreshToken = "token-to-kill";

      await authController.logout(req, res, next);

      expect(authService.logout).toHaveBeenCalledWith("token-to-kill");

      expect(res.clearCookie).toHaveBeenCalledWith("refreshToken", {
        ...cookieConfig,
        maxAge: 0,
      });

      expect(res.status).toHaveBeenCalledWith(204);
      expect(res.end).toHaveBeenCalled();
    });

    it("should pass errors to next()", async () => {
      authService.logout.mockRejectedValue(new Error("Redis down"));
      await authController.logout(req, res, next);
      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });
  });

  // =================================================================
  // LOGOUT ALL TESTS
  // =================================================================
  describe("logoutAll", () => {
    it("should use req.user.id if available (Middleware Auth)", async () => {
      req.user = { id: 123 }; // Simulating auth middleware

      await authController.logoutAll(req, res, next);

      expect(authService.logoutAll).toHaveBeenCalledWith(123);
      expect(res.clearCookie).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(204);
    });

    it("should return 401 if req.user is missing", async () => {
      req.user = undefined;

      await authController.logoutAll(req, res, next);

      expect(authService.logoutAll).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ message: "Unauthorized" });
    });



    it("should pass errors to next()", async () => {
      req.user = { id: 1 };
      authService.logoutAll.mockRejectedValue(new Error("Failed"));

      await authController.logoutAll(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });
  });
});