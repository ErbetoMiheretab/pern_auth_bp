require("dotenv").config();

export const env = process.env.NODE_ENV;
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
export const bcrypt = { saltRounds: parseInt(process.env.SALT_ROUNDS, 10) || 12 };
