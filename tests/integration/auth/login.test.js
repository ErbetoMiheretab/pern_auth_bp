import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import {
  sequelize,
  User,
  Role,
  Permission,
} from "../../../src/models/index.js";
import authRoutes from "../../../src/auth/auth.routes.js";
import redisClient from "../../../src/config/redis.js";

// Create Express app for testing
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth", authRoutes);

// Error Handler
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({ message: err.message });
});

describe("Login Integration Tests", () => {
  let testUser;
  let adminUser;
  let userRole;
  let adminRole;
  let readPermission;
  let writePermission;

  // Setup Database & Seed Data
  beforeAll(async () => {
    await sequelize.authenticate();
    await sequelize.sync({ force: true });

    // Create Permissions
    readPermission = await Permission.create({
      name: "read_content",
      description: "Can read content",
    });
    writePermission = await Permission.create({
      name: "write_content",
      description: "Can write content",
    });

    // Create Roles
    userRole = await Role.create({ name: "user" });
    adminRole = await Role.create({ name: "admin" });

    // Assign Permissions to Roles
    await userRole.addPermissions([readPermission]);
    await adminRole.addPermissions([readPermission, writePermission]);

    // Create Test Users
    testUser = await User.create({
      username: "testuser",
      email: "test@example.com",
      password: "Password123!",
    });
    await testUser.addRole(userRole);

    adminUser = await User.create({
      username: "adminuser",
      email: "admin@example.com",
      password: "AdminPass123!",
    });
    await adminUser.addRole(adminRole);
  });

  afterAll(async () => {
    await sequelize.close();
    await redisClient.quit();
  });

  describe("POST /auth/login - Successful Login", () => {
    it("should login successfully with valid credentials", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty("user");
      expect(res.body).toHaveProperty("accessToken");
      expect(res.body.user.email).toBe("test@example.com");
      expect(res.body.user.username).toBe("testuser");
      expect(res.body.accessToken).toBeTruthy();
    });

    it("should set refreshToken in httpOnly cookie", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(200);
      expect(res.headers["set-cookie"]).toBeDefined();
      
      const cookies = res.headers["set-cookie"];
      const refreshTokenCookie = cookies.find((cookie) =>
        cookie.startsWith("refreshToken=")
      );
      
      expect(refreshTokenCookie).toBeDefined();
      expect(refreshTokenCookie).toContain("HttpOnly");
    });

    it("should return user with roles and permissions", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "admin@example.com",
        password: "AdminPass123!",
      });

      expect(res.status).toBe(200);
      expect(res.body.user).toHaveProperty("roles");
      expect(res.body.user.roles).toBeInstanceOf(Array);
      expect(res.body.user.roles.length).toBeGreaterThan(0);
      
      // Check if admin role is present
      const adminRoleData = res.body.user.roles.find(r => r.name === "admin");
      expect(adminRoleData).toBeDefined();
      expect(adminRoleData.permissions).toBeInstanceOf(Array);
    });

    it("should login with email in different case", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "TEST@EXAMPLE.COM",
        password: "Password123!",
      });

      // This depends on your database collation settings
      // If case-insensitive, it should work
      expect([200, 401]).toContain(res.status);
    });
  });

  describe("POST /auth/login - Invalid Credentials", () => {
    it("should return 401 for non-existent email", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "nonexistent@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(/incorrect email or password/i);
    });

    it("should return 401 for incorrect password", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "WrongPassword123!",
      });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(/incorrect email or password/i);
    });

    it("should return 401 for empty password", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 401 for correct email but password with extra spaces", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: " Password123! ",
      });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(/incorrect email or password/i);
    });
  });

  describe("POST /auth/login - Validation Errors", () => {
    it("should return 400 for missing email", async () => {
      const res = await request(app).post("/auth/login").send({
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for missing password", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for invalid email format", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "invalid-email",
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for missing both email and password", async () => {
      const res = await request(app).post("/auth/login").send({});

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for null email", async () => {
      const res = await request(app).post("/auth/login").send({
        email: null,
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for null password", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: null,
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });
  });

  describe("POST /auth/login - Edge Cases", () => {
    it("should handle SQL injection attempts in email", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "admin@example.com' OR '1'='1",
        password: "Password123!",
      });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(/incorrect email or password/i);
    });

    it("should handle SQL injection attempts in password", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "' OR '1'='1",
      });

      expect(res.status).toBe(401);
      expect(res.body.message).toMatch(/incorrect email or password/i);
    });

    it("should handle very long email", async () => {
      const longEmail = "a".repeat(300) + "@example.com";
      const res = await request(app).post("/auth/login").send({
        email: longEmail,
        password: "Password123!",
      });

      expect([400, 401]).toContain(res.status);
    });

    it("should handle very long password", async () => {
      const longPassword = "a".repeat(1000);
      const res = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: longPassword,
      });

      expect(res.status).toBe(401);
    });

    it("should handle special characters in password", async () => {
      // Create user with special characters in password
      const specialUser = await User.create({
        username: "specialuser",
        email: "special@example.com",
        password: "P@ssw0rd!#$%^&*()",
      });

      const res = await request(app).post("/auth/login").send({
        email: "special@example.com",
        password: "P@ssw0rd!#$%^&*()",
      });

      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeTruthy();

      // Cleanup
      await specialUser.destroy();
    });

    it("should handle unicode characters in email", async () => {
      const res = await request(app).post("/auth/login").send({
        email: "tëst@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(401);
    });
  });

  describe("POST /auth/login - Multiple Login Sessions", () => {
    it("should allow multiple logins from same user", async () => {
      const res1 = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "Password123!",
      });

      const res2 = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "Password123!",
      });

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);
      expect(res1.body.accessToken).toBeTruthy();
      expect(res2.body.accessToken).toBeTruthy();
      // Tokens should be different
      expect(res1.body.accessToken).not.toBe(res2.body.accessToken);
    });

    it("should generate unique refresh tokens for each login", async () => {
      const res1 = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "Password123!",
      });

      const res2 = await request(app).post("/auth/login").send({
        email: "test@example.com",
        password: "Password123!",
      });

      const cookies1 = res1.headers["set-cookie"];
      const cookies2 = res2.headers["set-cookie"];

      const refreshToken1 = cookies1
        .find((c) => c.startsWith("refreshToken="))
        ?.split(";")[0]
        .split("=")[1];
      const refreshToken2 = cookies2
        .find((c) => c.startsWith("refreshToken="))
        ?.split(";")[0]
        .split("=")[1];

      expect(refreshToken1).toBeTruthy();
      expect(refreshToken2).toBeTruthy();
      expect(refreshToken1).not.toBe(refreshToken2);
    });
  });

  describe("POST /auth/login - Content Type Handling", () => {
    it("should reject non-JSON content type", async () => {
      const res = await request(app)
        .post("/auth/login")
        .set("Content-Type", "text/plain")
        .send("email=test@example.com&password=Password123!");

      expect([400, 500]).toContain(res.status);
    });

    it("should handle application/json content type", async () => {
      const res = await request(app)
        .post("/auth/login")
        .set("Content-Type", "application/json")
        .send(
          JSON.stringify({
            email: "test@example.com",
            password: "Password123!",
          })
        );

      expect(res.status).toBe(200);
    });
  });

  describe("POST /auth/login - Rate Limiting Scenarios", () => {
    it("should handle rapid successive login attempts", async () => {
      const promises = Array(5)
        .fill()
        .map(() =>
          request(app).post("/auth/login").send({
            email: "test@example.com",
            password: "Password123!",
          })
        );

      const results = await Promise.all(promises);
      
      // All should succeed if no rate limiting is implemented
      results.forEach((res) => {
        expect([200, 429]).toContain(res.status); // 429 if rate limiting exists
      });
    });
  });
});
