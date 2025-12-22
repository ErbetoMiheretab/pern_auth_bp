import { Sequelize } from "sequelize";
import { db, env } from "./vars.js";

const dbName = env === "test" ? db.testName || "pernAuthTest" : db.name;

const sequelize = new Sequelize(dbName, db.user, db.password, {
  host: db.host,
  port: db.port,
  dialect: "postgres",
  logging: env === "test" ? false : console.log,
  pool: { max: 50, min: 5, acquire: 30000, idle: 10000 },
});


export default sequelize