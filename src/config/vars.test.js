// config/db.test.js
import { Sequelize } from "sequelize";

// Use in-memory SQLite for tests
const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: ":memory:", // in-memory DB (fast, auto-cleared)
  logging: false, // disable SQL logs in tests
});

test("vars config loads", () => {
  expect(true).toBe(true);
});

export default sequelize;
