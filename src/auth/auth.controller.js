import * as authService from "./auth.service.js";
import { cookieConfig } from "../utils/tokens.js";

/**
 * Handle new user registration
 */
export const register = async (req, res, next) => {
  try {
    const { user, accessToken, refreshToken } = await authService.register(
      req.body
    );

    // Set Refresh Token in HttpOnly Cookie
    res.cookie("refreshToken", refreshToken, cookieConfig);

    res.status(201).json({
      user,
      accessToken,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Handle user login
 */
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const { user, accessToken, refreshToken } = await authService.login(
      email,
      password
    );

    // Set Refresh Token in HttpOnly Cookie
    res.cookie("refreshToken", refreshToken, cookieConfig);

    res.json({
      user,
      accessToken,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Handle token refresh
 */
export const refresh = async (req, res, next) => {
  try {
    // Prefer cookie, fallback to body
    const token = req.cookies?.refreshToken || req.body.refreshToken;
    const { accessToken, refreshToken } = await authService.refresh(token);

    // Update Refresh Token Cookie (Rotation)
    res.cookie("refreshToken", refreshToken, cookieConfig);

    res.json({
      accessToken,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Handle logout (single session)
 */
export const logout = async (req, res, next) => {
  try {
    const token = req.cookies?.refreshToken || req.body.refreshToken;
    await authService.logout(token);

    // Clear the cookie
    res.clearCookie("refreshToken", { ...cookieConfig, maxAge: 0 });

    res.status(204).end();
  } catch (error) {
    next(error);
  }
};

/**
 * Handle logout from all devices
 */
export const logoutAll = async (req, res, next) => {
  try {
    // Ideally requires authentication middleware to ensure req.user exists
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    await authService.logoutAll(userId);

    // Clear local cookie as well
    res.clearCookie("refreshToken", { ...cookieConfig, maxAge: 0 });

    res.status(204).end();
  } catch (error) {
    next(error);
  }
};
