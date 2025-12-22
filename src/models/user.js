import { DataTypes } from "sequelize";
import bcrypt from "bcrypt";
import vars from "../config/vars.js";

export default (sequelize) => {
  const User = sequelize.define(
    "User",
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      username: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: { isEmail: true },
      },
      passwordHash: { type: DataTypes.STRING, allowNull: false },
      password: {
        type: DataTypes.VIRTUAL,
        set(value) {
          // Temporarily store the raw password to access in hooks or validation
          this.setDataValue("password", value);
        },
      },
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
    },

    {
      tableName: "users",
      timestamps: true,
      indexes: [{ unique: true, fields: ["email"] }],
      hooks: {
        beforeValidate: async (user) => {
          if (user.password) {
            const saltRounds = vars.bcrypt.saltRounds || 12;
            const salt = await bcrypt.genSalt(saltRounds);
            user.passwordHash = await bcrypt.hash(user.password, salt);
          }
        },
        beforeUpdate: async (user) => {
          if (user.changed("password")) {
            const saltRounds = vars.bcrypt.saltRounds || 12;
            const salt = await bcrypt.genSalt(saltRounds);
            user.passwordHash = await bcrypt.hash(user.password, salt);
          }
        },
      },
    }
  );
  User.prototype.validatePassword = async function (plain) {
    return bcrypt.compare(plain, this.passwordHash);
  };
  User.prototype.toJSON = function () {
    const values = { ...this.get() };
    delete values.passwordHash;
    delete values.password;
    return values;
  };
  return User;
};
