import express from "express";
import { register, login } from "../controller/authcontroller.js";
import { validateRegister } from "../middlewares/validatemiddleware.js";

const router = express.Router();

router.post("/register", validateRegister, register);
router.post("/login", login);

export default router;