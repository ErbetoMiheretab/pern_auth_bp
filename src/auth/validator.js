import Joi from "joi";

const signup = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().trim().required(),
  password: Joi.string().min(8).required(),
  role: Joi.string().valid("user", "admin").default("user"),
});

const login = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});
export default { signup, login };
