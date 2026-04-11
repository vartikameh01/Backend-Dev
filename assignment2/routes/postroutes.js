import express from "express";
import { createPost } from "../controller/postcontroller.js";
import { isAuth } from "../middlewares/authmiddleware.js";

const router = express.Router();

router.post("/", isAuth, createPost);

export default router;