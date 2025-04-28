import jwt from "jsonwebtoken"
import User from "../models/user.js"

export const generateToken = (user) => {
    return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" })
}

export const authMiddleware = async (req, res, next) => {
    try {
        // 1. Get token from Authorization header (format: "Bearer <token>")
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ message: "No token, authorization denied" });
        }

        // 2. Extract token (remove "Bearer ")
        const token = authHeader.split(" ")[1];

        if (!token) {
            return res.status(401).json({ message: "No token found in Authorization header" });
        }

        // 3. Verify JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // 4. Find user in database
        const user = await User.findById(decoded.id).select("-password");

        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        // 5. Attach user to request object
        req.user = user;
        next();

    } catch (error) {
        console.error("Auth Middleware Error:", error.message);

        // Specific error messages
        if (error.name === "JsonWebTokenError") {
            return res.status(401).json({ message: "Invalid token" });
        }
        if (error.name === "TokenExpiredError") {
            return res.status(401).json({ message: "Token expired" });
        }

        res.status(401).json({ message: "Authorization failed" });
    }
};

export const adminMiddleware = (req, res, next) => {
    if (req.user && req.user.role === "admin") {
        next()
    } else {
        res.status(403).json({ message: "Access denied. Admin role required." })
    }
}

