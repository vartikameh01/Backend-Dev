import express from "express";
import { register, login } from "../controllers/authcontroller.js";
import { loginLimiter } from "../middleware/ratelimiter.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", loginLimiter, login);

export default router;
