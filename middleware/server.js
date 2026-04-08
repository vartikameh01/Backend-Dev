import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";

import logger from "./middleware/logger.js";
import sanitize from "./middleware/sanitize.js";
import mfa from "./middleware/mfa.js";

import User from "./models/users.js";
import Product from "./models/product.js";

dotenv.config();

const app = express();

app.use(express.json());
app.use(logger);
app.use(sanitize);

// DB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("DB Connected"))
  .catch(err => console.log(err));

// ---------- ROUTES ----------

// Home
app.get("/", (req, res) => {
  res.send("Server Running ");
});

// Exercise 2 (MFA)
app.get("/secure", mfa, (req, res) => {
  res.send("Secure Data Accessed ");
});

// Exercise 3 (User Activity)
app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.send("User not found");

  await user.updateLogin();
  res.send("Login tracked");
});

app.post("/logout", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.send("User not found");

  await user.updateLogout();
  res.send("Logout tracked");
});

// Exercise 4 (Soft Delete)
app.post("/product", async (req, res) => {
  const product = await Product.create(req.body);
  res.json(product);
});

app.delete("/product/:id", async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.send("Not found");

  await product.softDelete();
  res.send("Soft deleted");
});

app.get("/products", async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

// Start server
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});