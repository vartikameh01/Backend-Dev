import express from "express";
const router = express.Router();

// Step 1
router.post("/step1", (req, res) => {
  req.session.formData = { name: req.body.name };
  res.send("Step 1 saved");
});

// Step 2
router.post("/step2", (req, res) => {
  req.session.formData.email = req.body.email;
  res.send("Step 2 saved");
});

// Final Step
router.get("/submit", (req, res) => {
  res.json(req.session.formData);
});

export default router;