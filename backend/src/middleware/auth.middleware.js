import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

// Middleware to protect routes/ check if the user is logged in
export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt; // to get the token from the cookie. to execute this line we need cookie-parser middleware. cookies.jwt means getting the token value form the cookie that was saved like `jwt token` if it was `Bearer token` then it will be req.cookies.Bearer

    if (!token) {
      return res.status(401).json({ message: "Unauthorized - No Token Provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET); // decode the token. It checks the token's signature against the secret key to ensure it hasn't been tampered with or altered.

    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized - Invalid Token" });
    }

    const user = await User.findById(decoded.userId).select("-password"); //uses the Mongoose library to retrieve a user document from the database based on the userId extracted from the decoded JWT payload. The - symbol indicates that the password field should be excluded

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;

    next();
  } catch (error) {
    console.log("Error in protectRoute middleware: ", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
