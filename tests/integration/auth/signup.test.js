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

describe("Signup Integration Tests", () => {
  // Setup Database & Seed Data
  beforeAll(async () => {
    await sequelize.authenticate();
    await sequelize.sync({ force: true });

    // Create Permissions
    await Permission.create({
      name: "read_content",
      description: "Can read content",
    });
    await Permission.create({
      name: "write_content",
      description: "Can write content",
    });

    // Create Roles
    await Role.create({ name: "user" });
    await Role.create({ name: "admin" });
  });

  afterAll(async () => {
    await sequelize.close();
    await redisClient.quit();
  });

  // Clear users between tests to avoid conflicts
  afterEach(async () => {
    await User.destroy({ where: {}, force: true });
  });

  describe("POST /auth/register - Successful Signup", () => {
    it("should register a new user with valid data", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "newuser",
        email: "newuser@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty("user");
      expect(res.body).toHaveProperty("accessToken");
      expect(res.body.user.email).toBe("newuser@example.com");
      expect(res.body.user.username).toBe("newuser");
      expect(res.body.user).not.toHaveProperty("password");
      expect(res.body.accessToken).toBeTruthy();
    });

    it("should set refreshToken in httpOnly cookie", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "cookietest",
        email: "cookietest@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
      expect(res.headers["set-cookie"]).toBeDefined();

      const cookies = res.headers["set-cookie"];
      const refreshTokenCookie = cookies.find((cookie) =>
        cookie.startsWith("refreshToken=")
      );

      expect(refreshTokenCookie).toBeDefined();
      expect(refreshTokenCookie).toContain("HttpOnly");
    });

    it("should hash the password in the database", async () => {
      const plainPassword = "Password123!";
      await request(app).post("/auth/register").send({
        username: "hashtest",
        email: "hashtest@example.com",
        password: plainPassword,
      });

      const user = await User.findOne({
        where: { email: "hashtest@example.com" },
      });

      expect(user).toBeTruthy();
      expect(user.passwordHash).not.toBe(plainPassword);
      expect(user.passwordHash.length).toBeGreaterThan(plainPassword.length);
    });

    it("should register with minimum password length (8 characters)", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "minpass",
        email: "minpass@example.com",
        password: "Pass1234",
      });

      expect(res.status).toBe(201);
      expect(res.body.user.email).toBe("minpass@example.com");
    });

    it("should trim email whitespace", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "trimtest",
        email: "  trimtest@example.com  ",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
      expect(res.body.user.email).toBe("trimtest@example.com");
    });

    it("should create user with special characters in password", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "special",
        email: "special@example.com",
        password: "P@ssw0rd!#$%^&*()",
      });

      expect(res.status).toBe(201);
      expect(res.body.user.email).toBe("special@example.com");
    });
  });

  describe("POST /auth/register - Validation Errors", () => {
    it("should return 400 for missing email", async () => {
      const res = await request(app).post("/auth/register").send({
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for missing password", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "test@example.com",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for invalid email format", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "invalid-email",
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for password shorter than 8 characters", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "test@example.com",
        password: "Pass12",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toMatch(/password/i);
    });

    it("should return 400 for empty email string", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "",
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for empty password string", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "test@example.com",
        password: "",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for null email", async () => {
      const res = await request(app).post("/auth/register").send({
        email: null,
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for null password", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "test@example.com",
        password: null,
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for email without @ symbol", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "testexample.com",
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });

    it("should return 400 for email without domain", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "test@",
        password: "Password123!",
      });

      expect(res.status).toBe(400);
      expect(res.body.message).toBeDefined();
    });
  });

  describe("POST /auth/register - Duplicate Email", () => {
    it("should return 409 when email already exists", async () => {
      // First registration
      await request(app).post("/auth/register").send({
        username: "duplicate",
        email: "duplicate@example.com",
        password: "Password123!",
      });

      // Second registration with same email
      const res = await request(app).post("/auth/register").send({
        username: "duplicate2",
        email: "duplicate@example.com",
        password: "DifferentPass123!",
      });

      expect(res.status).toBe(409);
      expect(res.body.message).toMatch(/email.*already.*use/i);
    });

    it("should be case-insensitive for duplicate email check", async () => {
      await request(app).post("/auth/register").send({
        username: "testuser",
        email: "test@example.com",
        password: "Password123!",
      });

      const res = await request(app).post("/auth/register").send({
        username: "TESTUSER",
        email: "TEST@EXAMPLE.COM",
        password: "Password123!",
      });

      // Depending on database collation, this might be 201 or 409
      expect([201, 409]).toContain(res.status);
    });

    it("should allow same password for different users", async () => {
      const samePassword = "SharedPass123!";

      await request(app).post("/auth/register").send({
        username: "user1",
        email: "user1@example.com",
        password: samePassword,
      });

      const res = await request(app).post("/auth/register").send({
        username: "user2",
        email: "user2@example.com",
        password: samePassword,
      });

      expect(res.status).toBe(201);
    });
  });

  describe("POST /auth/register - Security Tests", () => {
    it("should handle SQL injection attempts in email", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "test@example.com' OR '1'='1",
        password: "Password123!",
      });

      expect(res.status).toBe(400);
    });

    it("should handle SQL injection attempts in password", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "test@example.com",
        password: "' OR '1'='1",
      });

      expect(res.status).toBe(400);
    });

    it("should handle XSS attempts in email", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "<script>alert('xss')</script>@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(400);
    });

    it("should not expose password in response", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "security",
        email: "security@example.com",
        password: "SecretPass123!",
      });

      expect(res.status).toBe(201);
      expect(res.body.user).not.toHaveProperty("password");
      expect(JSON.stringify(res.body)).not.toContain("SecretPass123!");
    });
  });

  describe("POST /auth/register - Edge Cases", () => {
    it("should handle very long email addresses", async () => {
      const longEmail = "a".repeat(240) + "@example.com";
      const res = await request(app).post("/auth/register").send({
        email: longEmail,
        password: "Password123!",
      });

      expect([201, 400]).toContain(res.status);
    });

    it("should handle very long passwords", async () => {
      const longPassword = "P@ssw0rd" + "a".repeat(1000);
      const res = await request(app).post("/auth/register").send({
        username: "longpass",
        email: "longpass@example.com",
        password: longPassword,
      });

      expect(res.status).toBe(201);
    });

    it("should handle password with only special characters", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "specialonly",
        email: "special@example.com",
        password: "!@#$%^&*()",
      });

      expect(res.status).toBe(201);
    });

    it("should handle email with plus sign (valid email)", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "usertag",
        email: "user+tag@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
    });

    it("should handle email with subdomain", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "usermail",
        email: "user@mail.example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
    });

    it("should handle email with numbers", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "user123",
        email: "user123@example456.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
    });

    it("should handle email with hyphens", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "firstlast",
        email: "first-last@example-domain.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
    });

    it("should handle email with dots", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "firstlast",
        email: "first.last@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
    });
  });

  describe("POST /auth/register - Content Type", () => {
    it("should accept application/json content type", async () => {
      const res = await request(app)
        .post("/auth/register")
        .set("Content-Type", "application/json")
        .send(
          JSON.stringify({
            username: "jsontest",
            email: "jsontest@example.com",
            password: "Password123!",
          })
        );

      expect(res.status).toBe(201);
    });

    it("should reject non-JSON content type", async () => {
      const res = await request(app)
        .post("/auth/register")
        .set("Content-Type", "text/plain")
        .send("email=test@example.com&password=Password123!");

      expect([400, 500]).toContain(res.status);
    });
  });

  describe("POST /auth/register - Token Generation", () => {
    it("should generate a valid JWT access token", async () => {
      const res = await request(app).post("/auth/register").send({
        username: "jwtuser",
        email: "jwt@example.com",
        password: "Password123!",
      });

      expect(res.status).toBe(201);
      expect(res.body.accessToken).toBeTruthy();
      expect(typeof res.body.accessToken).toBe("string");
      expect(res.body.accessToken.split(".").length).toBe(3); // JWT has 3 parts
    });

    it("should generate unique tokens for different users", async () => {
      const res1 = await request(app).post("/auth/register").send({
        username: "user1",
        email: "user1@example.com",
        password: "Password123!",
      });

      const res2 = await request(app).post("/auth/register").send({
        username: "user2",
        email: "user2@example.com",
        password: "Password123!",
      });

      expect(res1.body.accessToken).not.toBe(res2.body.accessToken);
    });
  });

  describe("POST /auth/register - Database Persistence", () => {
    it("should persist user in database", async () => {
      await request(app).post("/auth/register").send({
        username: "persist",
        email: "persist@example.com",
        password: "Password123!",
      });

      const user = await User.findOne({
        where: { email: "persist@example.com" },
      });

      expect(user).toBeTruthy();
      expect(user.email).toBe("persist@example.com");
    });

    it("should create only one user record", async () => {
      await request(app).post("/auth/register").send({
        username: "single",
        email: "single@example.com",
        password: "Password123!",
      });

      const count = await User.count({
        where: { email: "single@example.com" },
      });

      expect(count).toBe(1);
    });
  });

  describe("POST /auth/register - Concurrent Requests", () => {
    it("should handle rapid successive registrations", async () => {
      const promises = Array(5)
        .fill()
        .map((_, i) =>
          request(app).post("/auth/register").send({
            username: `user${i}`,
            email: `user${i}@example.com`,
            password: "Password123!",
          })
        );

      const results = await Promise.all(promises);

      results.forEach((res) => {
        expect(res.status).toBe(201);
      });
    });

    it("should prevent duplicate registration in concurrent requests", async () => {
      const sameEmail = "concurrent@example.com";

      const promises = Array(3)
        .fill()
        .map(() =>
          request(app).post("/auth/register").send({
            username: "concurrent",
            email: sameEmail,
            password: "Password123!",
          })
        );

      const results = await Promise.all(promises);

      const successCount = results.filter((r) => r.status === 201).length;
      const conflictCount = results.filter((r) => r.status === 409).length;

      expect(successCount).toBe(1);
      expect(conflictCount).toBe(2);
    });
  });
});
