import { object, string } from "joi";
const signup = object({
  email: string().email().trim().required(),
  password: string().min(8).required(),
  role: string().valid("user", "admin").default("user"),
});
const login = object({
  email: string().email().required(),
  password: string().required(),
});
export default { signup, login };
