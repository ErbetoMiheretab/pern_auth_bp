import { jwt as jwtConfig } from "../config/vars.js";
import { verifyToken } from "../utils/tokens.js";
import { User, Role, Permission } from "../models/index.js";
// import { UnauthorizedError } from "../utils/errors.js";
/**
 * Middleware to authorize requests using Bearer token
 */
export const authorize = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      const error = new Error("Unauthorized");
      error.status = 401;
      throw error;
    }

    const token = authHeader.split(" ")[1];
    const decoded = verifyToken(token, jwtConfig.accessSecret);

    if (!decoded || !decoded.id) {
      const error = new Error("Unauthorized");
      error.status = 401;
      throw error;
    }
    // Fetch user from DB with Roles and Permissions
    const user = await User.findByPk(decoded.id, {
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

    if (!user) {
      const error = new Error("Unauthorized");
      error.status = 401;
      throw error;
    }

    // Flatten roles and permissions
    const roles = user.roles.map((r) => r.name);
    const permissions = user.roles.flatMap((r) =>
      r.permissions.map((p) => p.name)
    );
    // Unique permissions
    const uniquePermissions = [...new Set(permissions)];

    req.user = {
      id: user.id,
      email: user.email,
      roles,
      permissions: uniquePermissions,
    };

    next();
  } catch (error) {
    next(error);
  }
};


// In your permissions/authorization module

/**
 * Middleware to check for required roles
 * @param {...String} requiredRoles
 */
export const requireRole = (...requiredRoles) => {
  if (requiredRoles.length === 0) {
    throw new Error("At least one role must be specified");
  }

  return (req, res, next) => {
    if (!req.user || !Array.isArray(req.user.roles)) {
      const error = new Error("Authentication required");
      error.status = 401;
      return next(error);
    }

    const hasRequiredRole = requiredRoles.some((role) =>
      req.user.roles.includes(role)
    );

    if (!hasRequiredRole) {
      // console.warn("Authorization failed - invalid role", { userId: req.user.id });
      const error = new Error("Insufficient role");
      error.status = 403;
      return next(error);
    }

    next();
  };
};

/**
 * Middleware to check for required permissions
 * @param {...String} requiredPermissions
 */
export const requirePermission = (...requiredPermissions) => {
  if (requiredPermissions.length === 0) {
    throw new Error("At least one permission must be specified");
  }

  return (req, res, next) => {
    if (!req.user || !Array.isArray(req.user.permissions)) {
      const error = new Error("Authentication required");
      error.status = 401;
      return next(error);
    }

    const hasRequiredPermission = requiredPermissions.every((perm) =>
      req.user.permissions.includes(perm)
    );

    if (!hasRequiredPermission) {
      const error = new Error("Insufficient permission");
      error.status = 403;
      return next(error);
    }

    next();
  };
};