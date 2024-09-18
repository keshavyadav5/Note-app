const { errorHandler } = require("../utils/error");
const bcrypt = require('bcrypt');
const User = require('../modules/userModel');
const jwt = require('jsonwebtoken');

const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(errorHandler(400, "User already exists"));
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      email,
      password: hashedPassword,
    });

    await user.save();

    res.status(201).json({
      success: true,
      message: "User created successfully",
    });
  } catch (error) {
    console.log(error.message);
    next(error); 
  }
};

const login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json(errorHandler(400, "Invalid email or password"));
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json(errorHandler(400, "Invalid email or password"));
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    
    const { password: pass, ...userData } = user._doc;

    res.cookie("access_token", token, { 
      httpOnly: true, 
      sameSite: "None",
      secure: true
    }).status(200).json({
      success: true,
      message: "Login successful",
      userData
    });
  } catch (error) {
    res.status(500).json(error);
  }
};


const logout = async (req, res, next) => {
  try {
    res.clearCookie("access_token");

    res.status(200).json({
      success: true,
      message: "User logged out successfully"
    });
  } catch (error) {
    next(error);
  }
};

exports.signup = signup;
exports.login = login;
exports.logout = logout;
