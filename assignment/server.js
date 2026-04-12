import dotenv from "dotenv";
dotenv.config();

import express from "express";
import { sessionMiddleware } from "./config/session.js";

const app = express();

app.use(express.json());
app.use(sessionMiddleware);

app.listen(5000, () => console.log("Server running"));
