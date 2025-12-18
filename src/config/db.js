import { Sequelize } from "sequelize";
import { db, env } from "./vars";

const sequelize = new Sequelize(db.name, db.user, db.password, {
  host: db.host,
  port: db.port,
  dialect: "postgres",
  logging: env === "test" ? false : console.log,
  pool: { max: 5, min: 0, acquire: 30000, idle: 10000 },
});


export default sequelize