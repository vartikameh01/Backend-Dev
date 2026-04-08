import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

import formRoutes from "./routes/formRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import cartRoutes from "./routes/cartRoutes.js";
import langRoutes from "./routes/langRoutes.js";

dotenv.config();

const app = express();

app.use(express.json());
app.use(cookieParser());

// Session setup
app.use(
  session({
    secret: "secret123",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 5 * 60 * 1000 } // 5 min
  })
);

// Routes
app.use("/form", formRoutes);
app.use("/admin", adminRoutes);
app.use("/cart", cartRoutes);
app.use("/lang", langRoutes);

// Home
app.get("/", (req, res) => {
  res.send("Session Project Running ✅");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
app.get("/session-status", (req, res) => {
  if (!req.session.cookie.maxAge) {
    return res.send("No active session");
  }

  const timeLeft = req.session.cookie.maxAge / 1000;
  res.send(`Session expires in ${timeLeft} seconds`);
});