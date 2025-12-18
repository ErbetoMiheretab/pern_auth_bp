import { Sequelize } from "sequelize";
import vars from "../config/vars.js";

// Import model factories
import UserFactory from "./user.js";
import RoleFactory from "./role.js";
import UserRoleFactory from "./userRole.js";
import RefreshTokenFactory from "./refreshToken.js";

// 1. Initialize Sequelize depending on environment
const env = process.env.NODE_ENV || "development";

let sequelize;

if (env === "test") {
  sequelize = new Sequelize({
    dialect: "sqlite",
    storage: ":memory:",
    logging: false,
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

// 4. Export everything
export { sequelize, User, Role, UserRole, RefreshToken };
export default { sequelize, User, Role, UserRole, RefreshToken };
