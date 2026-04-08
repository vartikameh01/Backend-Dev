import express from "express";
import { isAuth, isAdmin } from "../middleware/auth.js";

const router = express.Router();

// Login
router.post("/login", (req, res) => {
  const { username } = req.body;

  // Demo user
  req.session.user = {
    username,
    role: username === "admin" ? "admin" : "user"
  };

  res.send("Logged in");
});

// Admin panel
router.get("/dashboard", isAuth, isAdmin, (req, res) => {
  res.send("Welcome Admin Panel 🔐");
});

export default router;