import { DataTypes } from "sequelize";

export default (sequelize) => {
  const RolePermission = sequelize.define(
    "RolePermission",
    {
      roleId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true,
      },
      permissionId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true,
      },
    },
    { tableName: "role_permissions", timestamps: false }
  );
  return RolePermission;
};
