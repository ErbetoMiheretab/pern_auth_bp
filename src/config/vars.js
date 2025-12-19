import dotenv from "dotenv";
dotenv.config();

export const env = process.env.NODE_ENV || "development";
export const port = process.env.PORT || 4000;

export const db = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  name: process.env.DB_NAME,
  testName: process.env.DB_TEST_NAME,
};

export const redis = {
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASS,
};

export const jwt = {
  accessSecret: process.env.ACCESS_SECRET,
  accessExpire: process.env.ACCESS_EXPIRE,
  refreshSecret: process.env.REFRESH_SECRET,
  refreshExpire: process.env.REFRESH_EXPIRE,
};

export const bcrypt = {
  saltRounds: parseInt(process.env.SALT_ROUNDS, 10) || 12,
};

// ---- ENV VALIDATION ----
const required = [
  "ACCESS_SECRET",
  "REFRESH_SECRET",
  "ACCESS_EXPIRE",
  "REFRESH_EXPIRE",
];

required.forEach((key) => {
  if (!process.env[key]) {
    throw new Error(`Missing required env var: ${key}`);
  }
});

// 👇 Add this at the bottom
export default { env, port, db, redis, jwt, bcrypt };
