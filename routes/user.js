import express from "express"
import { authMiddleware, adminMiddleware } from "../middleware/auth.js"
import User from "../models/user.js"
import dotenv from "dotenv";
import bcrypt from "bcryptjs"
import upload from "../middleware/upload.js";

dotenv.config(); // Load environment variables

const router = express.Router()

// admin only route to regiser admins with avaters
router.post("/admin/register", authMiddleware, adminMiddleware, upload.single("avatar"), async (req, res) => {
    try {
        const { username, email, password } = req.body;
        console.log(req.body);


        // Check if admin already exists
        const existingAdmin = await User.findOne({ email, role: "admin" });
        if (existingAdmin) {
            return res.status(400).json({ message: "Admin with this email already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Avatar handling (Cloudinary)
        let avatar = null;
        if (req.file) {
            avatar = {
                public_id: req.file.filename, // Cloudinary public_id
                url: req.file.path // Cloudinary secure URL
            };
        }

        // Create new admin
        const newAdmin = await User.create({
            username,
            email,
            password: hashedPassword,
            role: "admin",
            accountVerified: true, // Admins are verified by default
            avatar
        });

        res.status(201).json({ message: "Admin registered successfully", admin: newAdmin });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Admin only route get all users
router.get("/all", authMiddleware, adminMiddleware, async (req, res, next) => {
    try {
        const users = await User.find({ accountVerified: true }).select("-password")
        res.json(users)
    } catch (error) {
        next(error)
    }
})



export default router;

