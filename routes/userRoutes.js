const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const { userVerifyToken } = require("../middlewares/authMiddleware");

// router.use(userVerifyToken)

router.post("/send-otp", userController.sendOtp);
router.post("/confirm-otp", userController.confirmOtp);
router.post("/signup", userController.signup);
router.post("/login", userController.login);
router.post("/reset-password", userController.resetPassword);

module.exports = router;
