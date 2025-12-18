import { DataTypes } from "sequelize";
import bcrypt from "bcrypt";
import vars from "../config/vars";

export default (sequelize) => {
  const User = sequelize.define(
    "User",
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: { isEmail: true },
      },
      passwordHash: { type: DataTypes.STRING, allowNull: false },
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true },
    },

    {
      tableName: "users",
      timestamps: true,
      indexes: [{ unique: true, fields: ["email"] }],
      hooks: {
        beforeCreate: async (user) => {
          user.passwordHash = await bcrypt.hash(
            user.passwordHash,
            vars.bcrypt.saltRounds
          );
        },
        beforeUpdate: async (user) => {
          if (user.changed("passwordHash")) {
            user.passwordHash = await bcrypt.hash(
              user.passwordHash,
              vars.bcrypt.saltRounds
            );
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
    return values;
  };
  return User;
};
