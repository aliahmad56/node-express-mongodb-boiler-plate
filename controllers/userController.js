const userModel = require('../models/userModel')
const bcrypt = require("bcrypt")
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../helpers/sendEmail');
const { generateOtp } = require('../helpers/otpGenerate');

//used for verification user and forget password
const sendOtp = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({
        status: false,
        message: "Email is required.",
      });
    }

    // Generate a 6-digit OTP
    const otp = generateOtp();
    if (!otp) {
      return res.status(404).json({
        status: false,
        message: "Failed to generate otp",
      });
    }

    // Send OTP to email
    const emailSent = await sendEmail(
      email,
      "Verification OTP",
      `Use this OTP ${otp} to verify your account.`
    );

    if (!emailSent) {
      return res.status(500).json({
        status: false,
        message: "Failed to send verification email.",
      });
    }

    // Update user's verification OTP in the database
    const user = await userModel.findOneAndUpdate(
      { email: email },
      { userOtp: otp },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        status: false,
        message: "User not found.",
      });
    }

    return res.status(200).json({
      status: true,
      message: "Verification OTP has been sent to the email.",
    });
  } catch (err) {
    console.error("Error sending verification OTP:", err);
    return res.status(500).json({
      status: false,
      message: "Internal Server Error",
      err: err.message,
    });
  }
};

const confirmOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        status: false,
        message: "Email and OTP are required.",
      });
    }

    // Verify OTP and update user in a single query
    const user = await userModel.findOneAndUpdate(
      { email, userOtp: otp },
      {
        $set: {
          isVerified: true,
          userOtp: null, // Clear OTP after verification
        },
      },
      { new: true } // Returns the updated document
    );

    if (!user) {
      return res.status(400).json({
        status: false,
        message: "Invalid OTP or email. Please try again.",
      });
    }

    return res.status(200).json({
      status: true,
      message: "OTP verified successfully. Your account is now verified.",
    });
  } catch (err) {
    console.error("Error confirming OTP:", err);
    return res.status(500).json({
      status: false,
      message: "Internal Server Error",
      err: err.message,
    });
  }
};

const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        status: false,
        message: "All required fields must be provided.",
      });
    }

    const lowerCaseEmail = email?.toLowerCase();

    let existingUser = await userModel.findOne({
      // $or: [{ email: lowerCaseEmail }, { phoneno: phoneno }],
      email: lowerCaseEmail,
    });

    if (existingUser?.isVerified === false) {
      const otp = generateOtp();
      if (!otp) {
        return res.status(500).json({
          status: false,
          message: "Failed to generate OTP.",
        });
      }

      const emailSent = await sendEmail(lowerCaseEmail, "Verification OTP", `Use this OTP ${otp} to verify your account.`);
      if (!emailSent) {
        return res.status(500).json({
          status: false,
          message: "User created, but failed to send verification email.",
        });
      }

      existingUser.userOtp = otp;
      await existingUser.save();      

      return res.status(409).json({
        status: false,
        isVerified: false,
        message: "User already registered! Please check your email to verify account",
      });
    }

    if (existingUser) {
      return res.status(409).json({
        status: false,
        message: "User already registered and has active account",
      });
    }

    // Generate OTP
    const otp = generateOtp();
    if (!otp) {
      return res.status(500).json({
        status: false,
        message: "Failed to generate OTP.",
      });
    }

    // Encrypt password
    const encryptedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    let newUser = new userModel({
      name,
      email: lowerCaseEmail,
      userOtp: otp,
      password: encryptedPassword,
      isVerified: false,
    });

    // Save user
    await newUser.save();

    //comment for now
    // Send verification OTP via email
    const emailSent = await sendEmail(lowerCaseEmail, "Verification OTP", `Use this OTP ${otp} to verify your account.`);

    if (!emailSent) {
      return res.status(500).json({
        status: false,
        message: "User created, but failed to send verification email.",
      });
    }

    return res.status(201).json({
      status: true,
      message: "User registered successfully. Verification OTP sent.",
      user: newUser,
    });
  } catch (err) {
    console.error("Error:", err);
    return res.status(500).json({
      status: false,
      message: err.message || "Internal Server Error",
    });
  }
};

const login = async (req, res) => {
  try {
    console.log("req.body: ", req.body);
    const { email, password } = req.body;

    // Ensure email and password are provided
    if (!email || !password) {
      return res.status(400).json({
        status: false,
        message: "Email and password are required.",
      });
    }

    // Find the user by email
    const user = await userModel.findOne({ email: email.toLowerCase() });

    if (user) {
      // Check if user is deleted
      if (user.isDeleted == true) {
        return res.status(400).json({
          status: false,
          message: "This email user is deleted by admin",
        });
      }

      // Check if user is verified
      if (!user.isVerified) {
        // Generate a 6-digit OTP
        const otp = generateOtp();
        if (!otp) {
          return res.status(404).json({
            status: false,
            message: "Failed to generate otp",
          });
        }
        const emailSent = await sendEmail(
          email,
          "Verification OTP",
          `Use this OTP ${otp} to verify your account.`
        );

        if (!emailSent) {
          return res.status(500).json({
            status: false,
            message: "Failed to send verification otp to verify your account",
          });
        }
        return res.status(403).json({
          status: false,
          isVerified: false,
          message:
            "User is not verified. Please verify your account before logging in.",
        });
      }

      // Verify password
      const isPasswordMatch = await bcrypt.compare(password, user.password);
      if (isPasswordMatch) {
        // Generate access token if credentials are correct
        const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
          expiresIn: "2h",
        });

        return res.status(200).json({
          status: true,
          message: "Login successfull",
          user: user,
          accessToken: accessToken,
        });
      } else {
        // Password does not match
        return res.status(400).json({
          status: false,
          message: "Incorrect email or password.",
        });
      }
    } else {
      // User not found
      console.log("Invalid User");
      return res.status(400).json({
        status: false,
        message: "User does not exist.",
      });
    }
  } catch (err) {
    console.log("Error: ", err);
    return res.status(500).json({
      status: false,
      message: "Internal Server Error",
      err: err.message,
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { otp, password } = req.body;

    // Check if OTP and password are provided
    if (!otp || !password) {
      return res.status(400).json({
        status: false,
        message: "OTP and password are required.",
      });
    }

    // Encrypting the new password
    const encryptedPassword = await bcrypt.hash(password, saltRounds);
    console.log("Encrypted Password:", encryptedPassword);

    // Check if the OTP exists for a user
    const user = await userModel.findOne({ userOtp: otp });

    if (!user) {
      return res.status(404).json({
        status: false,
        message: "Invalid OTP. Please try again.",
      });
    }

    // Update the password and clear the OTP
    const updatePassword = await userModel.updateOne(
      { userOtp: otp },
      { $set: { userOtp: null, password: encryptedPassword } }
    );

    if (updatePassword.nModified > 0) {
      return res.status(200).json({
        status: true,
        message: "Password updated successfully.",
      });
    } else {
      return res.status(400).json({
        status: false,
        message:
          "Failed to update password. OTP might be expired or already used.",
      });
    }
  } catch (err) {
    console.error("Error:", err);
    if (err) {
      return res.status(422).json({
        status: false,
        message: err.message,
      });
    }
    return res.status(500).json({
      status: false,
      message: "Internal Server Error",
    });
  }
};


module.exports = {
  sendOtp,
  confirmOtp,
  signup,
  login,
  resetPassword
};
