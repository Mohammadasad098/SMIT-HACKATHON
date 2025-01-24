import User from "../models/user.models.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";








const generateAccessToken = (user) => {
  return jwt.sign({ email: user.email }, process.env.ACCESS_JWT_SECRET, {
    expiresIn: "6h",
  });
};
const generateRefreshToken = (user) => {
  return jwt.sign({ email: user.email }, process.env.REFRESH_JWT_SECRET, {
    expiresIn: "7d",
  });
};




const registerUser = async (req, res) => {
  const { userName, email, password } = req.body;

  // Validate inputs
  if (!userName) return res.status(400).json({ message: "username required" });
  if (!email) return res.status(400).json({ message: "email required" });
  if (!password) return res.status(400).json({ message: "password required" });

  try {
    // Check if user already exists
    const user = await User.findOne({ email });
    if (user) return res.status(401).json({ message: "user already exists" });

    // Create new user
    const createUser = await User.create({
      userName,
      email,
      password,
    });

    // Generate tokens
    const accessToken = generateAccessToken(createUser);
    const refreshToken = generateRefreshToken(createUser);

    // Set refresh token in cookie
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false });

    // Return response with tokens and user data
    res.json({
      message: "user registered and logged in successfully",
      accessToken,
      refreshToken,
      data: {
        userName: createUser.userName,
        email: createUser.email,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "server error", error });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  // Validate inputs
  if (!email) return res.status(400).json({ message: "email required" });
  if (!password) return res.status(400).json({ message: "password required" });

  try {
    // Find user
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "no user found" });

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(400).json({ message: "incorrect password" });

    // Generate tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Set refresh token in cookie
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false });

    // Return response with tokens and user data
    res.json({
      message: "user logged in successfully",
      accessToken,
      refreshToken,
      data: {
        userName: user.userName,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "server error", error });
  }
};


  export {registerUser , loginUser}