import { pool } from "../src/config/db";
import { quit } from "../src/config/redis";

afterAll(async () => {
  await pool.end();        // close Postgres
  await quit(); // close Redis
});