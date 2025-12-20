import request from "supertest";
import express from "express";
import jwt from "jsonwebtoken";
import {
  sequelize,
  User,
  Role,
  Permission,
} from "../../../src/models/index.js"; // Adjust path to your models/index.js
import { authorize, requireRole, requirePermission } from "../../../src/middleware/auth.js"; // Adjust path to your middleware
import { jwt as jwtConfig } from "../../../src/config/vars.js"; // Adjust path to vars
import redisClient from "../../../src/config/redis.js"; // To close redis after tests

// Create a simple Express app just for testing these middleware
const app = express();
app.use(express.json());

// 1. Setup Test Routes
app.get("/protected", authorize, (req, res) => {
  res.json({ message: "Success", user: req.user });
});

app.get("/admin-only", authorize, requireRole("admin"), (req, res) => {
  res.json({ message: "Welcome Admin" });
});

app.get("/write-access", authorize, requirePermission("write_content"), (req, res) => {
  res.json({ message: "Content Written" });
});

app.get("/multi-role", authorize, requireRole("admin", "user"), (req, res) => {
  res.json({ message: "Access Granted" });
});

app.get("/multi-perm", authorize, requirePermission("read_content", "write_content"), (req, res) => {
  res.json({ message: "Full Access" });
});

// Error Handler
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({ message: err.message });
});

describe("Authorization Integration (RBAC)", () => {
  let adminToken, userToken, noRoleToken, expiredToken, deletedUserToken, wrongSecretToken;

  // 2. Setup Database & Seed Data
  beforeAll(async () => {
    // Ensure we are connected
    await sequelize.authenticate();
    
    // WIPE DB and Sync (Ensure this is pointing to a TEST DB in your .env)
    await sequelize.sync({ force: true });

    // --- A. Create Permissions ---
    const permWrite = await Permission.create({ name: "write_content", description: "Can write posts" });
    const permRead = await Permission.create({ name: "read_content", description: "Can read posts" });

    // --- B. Create Roles ---
    const roleAdmin = await Role.create({ name: "admin" });
    const roleUser = await Role.create({ name: "user" });

    // --- C. Assign Permissions to Roles ---
    // Admin gets Write & Read
    await roleAdmin.addPermissions([permWrite, permRead]);
    // User gets Read only
    await roleUser.addPermissions([permRead]);

    // --- D. Create Users ---
    // 1. Admin User
    const adminUser = await User.create({
      username: "admin",
      email: "admin@test.com",
      password: "password123",
    });
    await adminUser.addRole(roleAdmin);

    // 2. Standard User
    const normalUser = await User.create({
      username: "user",
      email: "user@test.com",
      password: "password123",
    });
    await normalUser.addRole(roleUser);

    // 3. User with No Roles
    const guestUser = await User.create({
      username: "guest",
      email: "guest@test.com",
      password: "password123",
    });

    // --- E. Generate Tokens ---
    adminToken = jwt.sign({ id: adminUser.id }, jwtConfig.accessSecret, { expiresIn: "1h" });
    userToken = jwt.sign({ id: normalUser.id }, jwtConfig.accessSecret, { expiresIn: "1h" });
    noRoleToken = jwt.sign({ id: guestUser.id }, jwtConfig.accessSecret, { expiresIn: "1h" });

    // Edge Case Tokens
    expiredToken = jwt.sign({ id: normalUser.id }, jwtConfig.accessSecret, { expiresIn: "-1s" });
    wrongSecretToken = jwt.sign({ id: normalUser.id }, "wrong-secret-key", { expiresIn: "1h" });

    // Deleted User Token
    const deletedUser = await User.create({
      username: "deleted",
      email: "deleted@test.com",
      password: "password123",
    });
    deletedUserToken = jwt.sign({ id: deletedUser.id }, jwtConfig.accessSecret, { expiresIn: "1h" });
    await deletedUser.destroy();
  });

  afterAll(async () => {
    // Cleanup connections to prevent Jest from hanging
    await sequelize.close();
    await redisClient.quit();
  });

  // =================================================================
  // TEST CASES
  // =================================================================

  describe("Middleware: authorize", () => {
    it("should deny access if no token provided", async () => {
      const res = await request(app).get("/protected");
      expect(res.status).toBe(401);
    });

    it("should deny access if token is malformed", async () => {
      const res = await request(app)
        .get("/protected")
        .set("Authorization", "Bearer invalidToken");
      expect(res.status).toBe(401); // Or 500 depending on how verifyToken handles error throw
    });

    it("should deny access if token is expired", async () => {
      const res = await request(app)
        .get("/protected")
        .set("Authorization", `Bearer ${expiredToken}`);
      expect(res.status).toBe(401);
    });

    it("should deny access if token is signed with wrong secret", async () => {
      const res = await request(app)
        .get("/protected")
        .set("Authorization", `Bearer ${wrongSecretToken}`);
      expect(res.status).toBe(401);
    });

    it("should deny access if user no longer exists", async () => {
      const res = await request(app)
        .get("/protected")
        .set("Authorization", `Bearer ${deletedUserToken}`);
      expect(res.status).toBe(401);
    });

    it("should deny access if Authorization header format is invalid", async () => {
      const res = await request(app)
        .get("/protected")
        .set("Authorization", `Token ${adminToken}`); // Missing Bearer
      expect(res.status).toBe(401);
    });

    it("should allow access with valid token and populate req.user", async () => {
      const res = await request(app)
        .get("/protected")
        .set("Authorization", `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.user).toBeDefined();
      expect(res.body.user.email).toBe("admin@test.com");
      // Check if Flattening worked (from your authorize middleware logic)
      expect(res.body.user.roles).toContain("admin");
      expect(res.body.user.permissions).toContain("write_content");
    });
  });

  describe("Middleware: requireRole", () => {
    it("should allow access if user has the 'admin' role", async () => {
      const res = await request(app)
        .get("/admin-only")
        .set("Authorization", `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toBe("Welcome Admin");
    });

    it("should deny access (403) if user has 'user' role but needs 'admin'", async () => {
      const res = await request(app)
        .get("/admin-only")
        .set("Authorization", `Bearer ${userToken}`);

      expect(res.status).toBe(403);
      expect(res.body.message).toMatch(/insufficient role/i);
    });

    it("should deny access (403) if user has NO roles", async () => {
      const res = await request(app)
        .get("/admin-only")
        .set("Authorization", `Bearer ${noRoleToken}`);

      expect(res.status).toBe(403); // Or 401 depending on your implementation of empty roles
    });

    it("should allow access if user has one of the multiple required roles", async () => {
      // route requires 'admin' OR 'user'
      // adminToken has 'admin' -> Allow
      const resAdmin = await request(app)
        .get("/multi-role")
        .set("Authorization", `Bearer ${adminToken}`);
      expect(resAdmin.status).toBe(200);

      // userToken has 'user' -> Allow
      const resUser = await request(app)
        .get("/multi-role")
        .set("Authorization", `Bearer ${userToken}`);
      expect(resUser.status).toBe(200);
    });
  });

  describe("Middleware: requirePermission", () => {
    it("should allow access if user has 'write_content' permission (via Admin role)", async () => {
      const res = await request(app)
        .get("/write-access")
        .set("Authorization", `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toBe("Content Written");
    });

    it("should deny access if user lacks 'write_content' permission (Standard User)", async () => {
      // User only has 'read_content'
      const res = await request(app)
        .get("/write-access")
        .set("Authorization", `Bearer ${userToken}`);

      expect(res.status).toBe(403);
      expect(res.body.message).toMatch(/insufficient permission/i);
    });

    it("should allow access if user has ALL required permissions", async () => {
      // route requires 'read_content' AND 'write_content'
      // adminToken has both
      const res = await request(app)
        .get("/multi-perm")
        .set("Authorization", `Bearer ${adminToken}`);
      expect(res.status).toBe(200);
    });

    it("should deny access if user is missing one of the required permissions", async () => {
      // route requires 'read_content' AND 'write_content'
      // userToken has 'read_content' ONLY
      const res = await request(app)
        .get("/multi-perm")
        .set("Authorization", `Bearer ${userToken}`);
      expect(res.status).toBe(403);
    });
  });
});