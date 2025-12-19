import { User, Role, Permission } from "../models/index.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  tokenStore,
} from "../utils/tokens.js";
import { jwt as jwtConfig } from "../config/vars.js";

/**
 * Register a new user
 * @param {Object} userData
 * @returns {Promise<{user: Object, accessToken: String, refreshToken: String}>}
 */
export const register = async (userData) => {
  const existingUser = await User.findOne({ where: { email: userData.email } });
  if (existingUser) {
    const error = new Error("Email already in use");
    error.status = 409;
    throw error;
  }

  const user = await User.create(userData);
  /* 
     If you have a default role (e.g. 'user'), fetching it and associating it here is good practice.
     For now, we just return the user. If you want to return defaults, reload the user.
  */
  // const userWithRoles = await User.findByPk(user.id, {
  //   include: {
  //     model: Role,
  //     as: "roles",
  //     include: { model: Permission, as: "permissions" },
  //   },
  // });
  
  const userJson = user.toJSON();

  const accessToken = await generateAccessToken(userJson);
  const { token: refreshToken } = await generateRefreshToken(userJson);

  return { user: userJson, accessToken, refreshToken };
};

/**
 * Login with email and password
 * @param {String} email
 * @param {String} password
 * @returns {Promise<{user: Object, accessToken: String, refreshToken: String}>}
 */
export const login = async (email, password) => {
  const user = await User.findOne({ where: { email } });
  if (!user) {
    const error = new Error("Incorrect email or password");
    error.status = 401;
    throw error;
  }

  const isMatch = await user.validatePassword(password);
  if (!isMatch) {
    const error = new Error("Incorrect email or password");
    error.status = 401;
    throw error;
  }
  // Fetch with Roles and Permissions
  const userWithRoles = await User.findByPk(user.id, {
    include: {
      model: Role,
      as: "roles",
      include: {
        model: Permission,
        as: "permissions",
        through: { attributes: [] }, // Hide join table
      },
      through: { attributes: [] }, // Hide join table
    },
  });
  const userJson = userWithRoles.toJSON();
  const accessToken = await generateAccessToken(userJson);
  const { token: refreshToken } = await generateRefreshToken(userJson);

  return { user: userJson, accessToken, refreshToken };
};

/**
 * Refresh access token
 * @param {String} token - Refresh token
 * @returns {Promise<{accessToken: String, refreshToken: String}>}
 */
export const refresh = async (token) => {
  if (!token) {
    const error = new Error("Refresh token is required");
    error.status = 400;
    throw error;
  }

  const decoded = verifyToken(token, jwtConfig.refreshSecret);
  if (!decoded) {
    const error = new Error("Invalid or expired refresh token");
    error.status = 401;
    throw error;
  }

  const isRevoked = await tokenStore.isRevoked(decoded.jti);
  if (isRevoked) {
    const error = new Error("Token revoked");
    error.status = 401;
    throw error;
  }

  const isVersionValid = await tokenStore.isVersionValid(decoded);
  if (!isVersionValid) {
    const error = new Error("Token version mismatch (User logged out?)");
    error.status = 401;
    throw error;
  }

  // Fetch with Roles and Permissions
  const userWithRoles = await User.findByPk(decoded.sub, {
    include: {
      model: Role,
      as: "roles",
      include: {
        model: Permission,
        as: "permissions",
        through: { attributes: [] },
      },
      through: { attributes: [] },
    },
  });

  if (!userWithRoles) {
    const error = new Error("User not found");
    error.status = 404;
    throw error;
  }

  // Rotation: Revoke the old refresh token
  await tokenStore.revoke(decoded.jti, decoded);

  const userJson = userWithRoles.toJSON();
  const newAccessToken = await generateAccessToken(userJson);
  const { token: newRefreshToken } = await generateRefreshToken(userJson);

  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
};

/**
 * Logout (Revoke Refresh Token)
 * @param {String} token - Refresh token
 */
export const logout = async (token) => {
  if (!token) return;
  const decoded = verifyToken(token, jwtConfig.refreshSecret);
  if (decoded) {
    await tokenStore.revoke(decoded.jti, decoded);
  }
};

/**
 * Logout from all devices (Revoke all tokens for user)
 * @param {Number|String} userId
 */
export const logoutAll = async (userId) => {
  await tokenStore.revokeAllForUser(userId);
};