import express, { json } from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { port } from "./config/vars";
import { sequelize } from "./models";
import authRoutes from "./routes/auth.routes";
import protectedRoutes from "./routes/protected.routes";
// import ApiError from "./utils/ApiError";

const app = express();
app.use(helmet());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:3000",
    credentials: true,
  })
);
app.use(json());
app.use(cookieParser());
app.use("/api/auth", authRoutes);
// app.use("/api", protectedRoutes);
// app.use((err, req, res, next) => {
//   if (err instanceof ApiError)
//     return res.status(err.status).json({ message: err.message });
//   console.error(err);
//   res.status(500).json({ message: "Internal server error" });
// });

const PORT = port;
app.listen(PORT, async () => {
  await sequelize.authenticate();
  console.log(`Auth service running on ${PORT}`);
});
