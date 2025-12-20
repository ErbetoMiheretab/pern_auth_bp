import express, { json } from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { port } from "./config/vars.js";
import { sequelize } from "./models/index.js";
import authRoutes from "./auth/auth.routes.js";

import swaggerUi from "swagger-ui-express";
import { swaggerSpec } from "./config/swagger.js";

// import protectedRoutes from "./routes/protected.routes";
// import ApiError from "./utils/ApiError";

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
// app.use("/api", protectedRoutes);

// Swagger docs
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (status === 500) console.error(err);
  res.status(status).json({ message: err.message });
});

const PORT = port;
app.listen(PORT, async () => {
  await sequelize.authenticate();
  console.log(`Auth service running on ${PORT}`);
});
