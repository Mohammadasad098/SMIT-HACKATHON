import express from "express";
import { upload } from "../middleware/multer.middleware.js";
import { uploadImage } from "../controllers/data.controllers.js";

const router = express.Router();



router.post("/upload", upload.single("image"), uploadImage);

export default router;