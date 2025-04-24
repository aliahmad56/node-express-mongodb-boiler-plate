var mongoose = require("mongoose");

var Schema = mongoose.Schema;
var user = new Schema({
  name: {
    type: String,
  },

  email: {
    type: String,
  },

  userOtp: {
    type: String,
  },

  isVerified: {
    type: Boolean,
  },

  password: {
    type: String,
  },
});

module.exports = mongoose.model("User", user);
