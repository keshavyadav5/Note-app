const express = require('express')
const { signup, login, logout } = require('../controller/authController')
const { verifyToken } = require('../utils/verifyUser')
const router = express.Router()


router.post('/signup',signup)
router.post('/login',login)
router.get('/logout',verifyToken,logout)


module.exports = router