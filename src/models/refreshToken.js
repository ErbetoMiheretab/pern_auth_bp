import { DataTypes } from "sequelize";

export default (sequelize) => {
  const RefreshToken = sequelize.define(
    "RefreshToken",
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      token: { type: DataTypes.STRING(512), allowNull: false, unique: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      revokedAt: { type: DataTypes.DATE, allowNull: true },
    },
    {
      tableName: "refresh_tokens",
      timestamps: true,
      indexes: [{ unique: true, fields: ["token"] }, { fields: ["expiresAt"] }],
    }
  );
  return RefreshToken;
};
