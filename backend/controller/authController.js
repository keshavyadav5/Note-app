const { errorHandler } = require("../utils/error");
const bcrypt = require('bcrypt')
const User = require('../modules/userModel')
const jwt = require('jsonwebtoken')

const signup = async (req, res, next) => {
  const { username, email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(errorHandler(400, "User already exist"))
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  const user = new User({
    username,
    email,
    password: hashedPassword
  });

  try {
    await user.save()
    res.status(201).json({
      success: true,
      message: "User created successfully",
    })
  } catch (error) {
    next(error)
  }
}

const login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return next(errorHandler(400, "Invalid email or password"))
    }
    const isValidPassword = bcrypt.compareSync(password, user.password);
    if (!isValidPassword) {
      return next(errorHandler(400, "Invalid email or password"))
    }
    const token = jwt.sign({id:user.id},process.env.JWT_SECRET)
    const { password : pass,...rest} = user._doc
    res.cookie("access_token",token,{httpOnly : true}).status(200).json({
      success : true,
      message : "Login successfull",
      rest
    })
  } catch (error) {
    next(error)
  }
}

const logout = async (req,res) =>{
  res.clearCookie("access_token")

  res.status(200).json({
    success : true,
    message : "user logged out successfully"
  })
}

exports.signup = signup;
exports.login = login
exports.logout = logout