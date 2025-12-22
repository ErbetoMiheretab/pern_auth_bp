// server.js
import cluster from "cluster";
import os from "os";
import express, { json } from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { port } from "./config/vars.js";
import { sequelize } from "./models/index.js";
import authRoutes from "./auth/auth.routes.js";
import swaggerUi from "swagger-ui-express";
import { swaggerSpec } from "./config/swagger.js";

const PORT = port;
// const NUM_CPUS = os.cpus().length; // constant for number of CPUs
const NUM_CPUS = 4; 
if (cluster.isPrimary) {
  console.log(`Primary ${process.pid} is running. Forking ${NUM_CPUS} workers...`);

  for (let i = 0; i < NUM_CPUS; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker) => {
    console.log(`Worker ${worker.process.pid} died. Forking replacement...`);
    cluster.fork();
  });
} else {
  const app = express();

  app.use(helmet());
  app.use(
    cors({
      origin: process.env.CORS_ORIGIN || "http://localhost:4000",
      credentials: true,
    })
  );
  app.use(json());
  app.use(cookieParser());
  app.use("/api/auth", authRoutes);
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

  app.use((err, req, res, next) => {
    const status = err.status || 500;
    if (status === 500) console.error(err);
    // Log the specific worker and the error stack
    console.error(`[Worker ${process.pid}] 500 Error: ${err.message}`, err.stack);
    res.status(status).json({ message: err.message });
  });

  const server = app.listen(PORT, async () => {
    try {
      await sequelize.authenticate();
      console.log("Database connection established.");
      await sequelize.sync({ alter: true });
      console.log("Database schema synchronized.");
      console.log(`Worker ${process.pid} running on port ${PORT}`);
    } catch (err) {
      console.error("Unable to start the server:", err.message);
      process.exit(1);
    }
  });

  // Graceful shutdown handler
  const shutdown = async () => {
    console.log(`Worker ${process.pid} shutting down...`);
    server.close(async () => {
      try {
        await sequelize.close();
        console.log("Database connection closed.");
      } catch (err) {
        console.error("Error closing DB connection:", err.message);
      }
      process.exit(0);
    });
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}