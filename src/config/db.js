const { Sequelize, Model } = require("sequelize");
const vars = require("./vars");

const sequelize = new Sequelize(vars.db.name, vars.db.user, vars.db.password, {
  host: vars.db.host,
  port: vars.db.port,
  dialect: "postgres",
  logging: vars.env === "test" ? false : console.log,
  pool: { max: 5, min: 0, acquire: 30000, idle: 10000 },
});


module.exports = sequelize