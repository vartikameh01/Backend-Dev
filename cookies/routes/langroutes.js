import express from "express";
const router = express.Router();

// Set language
router.get("/set/:lang", (req, res) => {
  res.cookie("lang", req.params.lang, { maxAge: 24 * 60 * 60 * 1000 });
  res.send("Language set");
});

// Get language
router.get("/get", (req, res) => {
  res.send(`Language: ${req.cookies.lang || "en"}`);
});

export default router;