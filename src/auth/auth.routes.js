import express from "express";
import * as controller from "./auth.controller.js";
import schemas from "./validator.js";
import { authorize } from "../middleware/auth.js";

const router = express.Router();

// Validation Middleware
const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body, { abortEarly: false });
  if (error) {
    const errorMessages = error.details.map((detail) => detail.message);
    const err = new Error(errorMessages.join(", "));
    err.status = 400;
    return next(err);
  }
  next();
};

/**
 * @route POST /auth/register
 */
router.post("/register", validate(schemas.signup), controller.register);

/**
 * @route POST /auth/login
 */
router.post("/login", validate(schemas.login), controller.login);

/**
 * @route POST /auth/refresh
 */
router.post("/refresh", controller.refresh);

/**
 * @route POST /auth/logout
 */
router.post("/logout", controller.logout);

/**
 * @route POST /auth/logout-all
 * Note: In a real app, you'd protect this with an authentication middleware
 * to ensure req.user is populated.
 */
router.post("/logout-all", authorize, controller.logoutAll);

export default router;
