const jwt = require("jsonwebtoken");
require("dotenv").config();

const userVerifyToken = (req, res, next) => {
  try {
    const token = req.header("Authorization");

    if (!token) {
      return res.status(401).json({
        status: false,
        message: "Access denied. No token provided.",
      });
    }
    console.log("Here reach at token", token);

    const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);

    req.email = decoded.email;
    req.userId = decoded.id;

    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Invalid token. Login Again" });
  }
};


module.exports = {
  userVerifyToken
};
