import express from "express";
import { sendMessage } from "../controller/messagecontroller.js";
import { isAuth } from "../middlewares/authmiddleware.js";

const router = express.Router();

router.post("/", isAuth, sendMessage);

export default router;