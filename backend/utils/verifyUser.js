const { errorHandler } = require("./error")
const jwt = require('jsonwebtoken')

const verifyToken = (req, res, next) => {
  try {
    const token = req.cookies.access_token
    if (!token) {
      return res.json(errorHandler(401, "Unauthorized"))
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res.json(errorHandler(403, "Forbidden"))
      }
      req.user = user
      next()
    })
  } catch (error) {
    console.log(error.message)
  }
}


exports.verifyToken = verifyToken