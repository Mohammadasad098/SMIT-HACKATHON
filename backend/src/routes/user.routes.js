import express from "express";
import { loginUser, logoutUser, refreshToken, registerUser } from "../controllers/user.controllers.js";

const router = express.Router();


router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/logout", logoutUser);
router.post("/refreshToken", refreshToken);

export default router;