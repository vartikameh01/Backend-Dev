import express from "express";
const router = express.Router();

// Add to cart
router.post("/add", (req, res) => {
  const item = req.body.item;

  if (req.session.user) {
    // Logged-in user → session cart
    if (!req.session.cart) req.session.cart = [];
    req.session.cart.push(item);
  } else {
    // Anonymous → cookie cart
    let cart = req.cookies.cart ? JSON.parse(req.cookies.cart) : [];
    cart.push(item);
    res.cookie("cart", JSON.stringify(cart));
  }

  res.send("Item added");
});

// View cart
router.get("/", (req, res) => {
  if (req.session.user) {
    return res.json(req.session.cart || []);
  } else {
    return res.json(req.cookies.cart ? JSON.parse(req.cookies.cart) : []);
  }
});

// Cart migration on login
router.get("/migrate", (req, res) => {
  if (!req.session.user) return res.send("Login first");

  let cookieCart = req.cookies.cart
    ? JSON.parse(req.cookies.cart)
    : [];

  req.session.cart = [...(req.session.cart || []), ...cookieCart];

  res.clearCookie("cart");
  res.send("Cart migrated");
});

export default router;