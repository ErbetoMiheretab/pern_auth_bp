import sequelize from "./config/db";
import setupModels from "./models";

const models = setupModels(sequelize)