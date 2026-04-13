import dotenv from "dotenv";
dotenv.config();

import express from "express";
import helmet from "helmet";

import { connectDB } from "./config/db.js";
import { sessionMiddleware } from "./config/session.js";
import { corsConfig } from "./config/cors.js";

import authRoutes from "./routes/authroutes.js";
import postRoutes from "./routes/postroutes.js";
import messageRoutes from "./routes/messageroutes.js";

const app = express();

connectDB();

app.use(express.json());
app.use(helmet());
app.use(corsConfig);
app.use(sessionMiddleware);

// Routes
app.use("/auth", authRoutes);
app.use("/posts", postRoutes);
app.use("/messages", messageRoutes);

app.get("/", (req, res) => {
  res.send("ConnectHub API running 🚀");
});

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});