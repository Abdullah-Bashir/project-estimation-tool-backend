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

// Rate limiting setup
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                 // adjust as needed
  message: "Too many requests from this IP, please try again later.",
});

// CORS middleware configuration
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      const normalizedOrigin = origin.replace(/\/$/, "");
      const allowedOrigin = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
      if (normalizedOrigin === allowedOrigin) {
        callback(null, true);
      } else {
        console.error(`CORS error: Request from origin "${normalizedOrigin}" not allowed.`);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

// Standard middleware
app.use(express.json());
app.use(cookieParser());
app.use(limiter);

// Simple home route
app.get("/", (_req, res) => {
  res.send("Welcome to the react Backend!");
});

// API routes
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/projects", projectDetailsRoutes);

// Error handling middleware
app.use(errorHandler);

// MongoDB connection
mongoose.set("strictQuery", false);
mongoose
  .connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("✅ Connected to MongoDB");

    // Start the cron job for removing unverified users
    const { default: removeUnverifiedUsers } = await import(
      "./services/removeUnverifiedAccounts.js"
    );
    removeUnverifiedUsers();
  })
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// —— Bind to the Railway-provided port —— //
const PORT = process.env.PORT;
if (!PORT) {
  console.error("❌ ERROR: no PORT environment variable defined. Exiting.");
  process.exit(1);
}

// Quick debug print
console.log({
  PORT,
  NODE_ENV: process.env.NODE_ENV,
  FRONTEND_URL: process.env.FRONTEND_URL,
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server listening on port ${PORT}`);
});
