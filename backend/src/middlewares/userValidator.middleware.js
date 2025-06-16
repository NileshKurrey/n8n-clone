import jwt from "jsonwebtoken";
import { db } from "../libs/db.js";
import { ApiError } from "../libs/api-error.js";
export const isUserLoggedIn = async (req, res, next) => {
  try {

    let token = req.cookies?.accessToken;

    if (!token && req.headers.authorization?.startsWith("Bearer ")) {
      token = req.headers.authorization.split(" ")[1];
    }

 

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication failed! No token provided.",
      });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
  
      return res.status(401).json({
        success: false,
        message: "Invalid or expired token.",
        error: err.message,
      });
    }
  } catch (err) {
    console.error("Auth middleware failure:", err.message);
    return res.status(500).json({
      success: false,
      message: "Server error during authentication.",
      error: err.message,
    });
  }
};


export const checkAdmin = async (req, res, next) => {
  try {
    const userId = req.user.id;
    console.log("UserId :", userId);
    const user = await db.user.findUnique({
      where: { id: userId },
      select: { role: true },
    });
    if (!user || user.role !== "ADMIN") {
      return res
        .status(403)
        .json(new ApiError(403, "Access denied - Admins only!"));
    }
    next();
  } catch (error) {
    console.log("Error checking admin role (auth.middleware.js): ", error);
    return res.status(500).json(new ApiError(500, "Error checking admin role"));
  }
};