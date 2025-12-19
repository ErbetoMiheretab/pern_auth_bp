import { Sequelize } from "sequelize";
import vars from "../config/vars.js";

// Import model factories
import UserFactory from "./user.js";
import RoleFactory from "./role.js";
import UserRoleFactory from "./userRole.js";
import RefreshTokenFactory from "./refreshToken.js";
import PermissionFactory from "./permission.js";
import RolePermissionFactory from "./rolePermission.js";

// 1. Initialize Sequelize depending on environment
const env = process.env.NODE_ENV || "development";

let sequelize;

if (env === "test") {
  // Use real DB for tests (injected via env vars)
  const { db } = vars;
  sequelize = new Sequelize(db.testName || "pernAuthTest", db.user, db.password, {
    host: db.host,
    port: db.port,
    dialect: "postgres",
    logging: false, // set to console.log to see SQL queries
  });
} else {
  const { db } = vars;
  sequelize = new Sequelize(db.name, db.user, db.password, {
    host: db.host,
    port: db.port,
    dialect: "postgres",
    logging: false,
  });
}

// 2. Initialize models from their factories
const User = UserFactory(sequelize);
const Role = RoleFactory(sequelize);
const UserRole = UserRoleFactory(sequelize);
const RefreshToken = RefreshTokenFactory(sequelize);
const Permission = PermissionFactory(sequelize);
const RolePermission = RolePermissionFactory(sequelize);

// 3. Define associations
User.belongsToMany(Role, {
  through: UserRole,
  as: "roles",
  foreignKey: "userId",
  otherKey: "roleId",
});

Role.belongsToMany(User, {
  through: UserRole,
  as: "users",
  foreignKey: "roleId",
  otherKey: "userId",
});
User.hasMany(RefreshToken, { foreignKey: "userId", as: "refreshTokens" });
RefreshToken.belongsTo(User, { foreignKey: "userId" });

Role.belongsToMany(Permission, {
  through: RolePermission,
  as: "permissions",
  foreignKey: "roleId",
  otherKey: "permissionId",
});

Permission.belongsToMany(Role, {
  through: RolePermission,
  as: "roles",
  foreignKey: "permissionId",
  otherKey: "roleId",
});

// 4. Export everything
export { sequelize, User, Role, UserRole, RefreshToken, Permission, RolePermission };
export default { sequelize, User, Role, UserRole, RefreshToken, Permission, RolePermission };
