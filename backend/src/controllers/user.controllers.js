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


  if (!userName) return res.status(400).json({ message: "username required" });
  if (!email) return res.status(400).json({ message: "email required" });
  if (!password) return res.status(400).json({ message: "password required" });

  try {
    const user = await User.findOne({ email });
    if (user) return res.status(401).json({ message: "user already exists" });


    const createUser = await User.create({
      userName,
      email,
      password,
    });


    const accessToken = generateAccessToken(createUser);
    const refreshToken = generateRefreshToken(createUser);

    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false });


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


  if (!email) return res.status(400).json({ message: "email required" });
  if (!password) return res.status(400).json({ message: "password required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "no user found" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(400).json({ message: "incorrect password" });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false });
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


const logoutUser = async (req, res) => {
  res.clearCookie("refreshToken");
  res.json({ message: "user logout successfully" });
};

const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
  if (!refreshToken)
    return res.status(401).json({ message: "no refresh token found!" });
  const decodedToken = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET);
  const user = await User.findOne({ email: decodedToken.email });
  if (!user) return res.status(404).json({ message: "invalid token" });
  const generateToken = generateAccessToken(user);
  res.json({ message: "access token generated", accesstoken: generateToken });
  res.json({ decodedToken });
};

export { registerUser, loginUser , logoutUser , refreshToken} 