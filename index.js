// index.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";

import authRoutes from "./routes/auth.js";
import userRoutes from "./routes/user.js";
import projectDetailsRoutes from "./routes/projectDetails.js";
import { errorHandler } from "./middleware/errorHandler.js";

const app = express();

// Rate limiting
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 100,
    message: "Too many requests from this IP, please try again later.",
  })
);

// CORS
// app.use(
//   cors({
//     origin: (origin, callback) => {
//       if (!origin) return callback(null, true);
//       const normalized = origin.replace(/\/$/, "");
//       const allowed = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
//       if (normalized === allowed) return callback(null, true);
//       console.error(`CORS blocked: ${normalized}`);
//       callback(new Error("Not allowed by CORS"));
//     },
//     credentials: true,
//   })
// );

app.use(
    cors({
      origin: ["https://project-management-tool-neon.vercel.app", "http://localhost:3000"],
      methods: ["GET","POST","OPTIONS", "PUT"],
      allowedHeaders: ["Content-Type","Authorization"],
    })
);

// Standard middleware
app.use(express.json());
app.use(cookieParser());

// Routes
app.get("/", (_req, res) => res.send("Welcome to the react Backend!"));
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/projects", projectDetailsRoutes);

// Error handler
app.use(errorHandler);

// Connect to MongoDB
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("✅ Connected to MongoDB");
    const { default: removeUnverifiedUsers } = await import(
      "./services/removeUnverifiedAccounts.js"
    );
    removeUnverifiedUsers();
  })
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// Listen on Railway-provided port or any available port (0)
const desiredPort = Number(process.env.PORT) || 0;
const server = app.listen(desiredPort, "0.0.0.0", () => {
  const { port } = server.address();
  console.log(`🚀 Server listening on port ${port}`);
});
