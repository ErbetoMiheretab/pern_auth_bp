import { DataTypes } from "sequelize";


export default (sequelize) => {
  const UserRole = sequelize.define(
    "UserRole",
    {
      userId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true,
      },
      roleId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true,
      },
    },
    { tableName: "user_roles", timestamps: false }
  );
  return UserRole;
};
