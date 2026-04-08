import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  lastLogin: Date,
  lastLogout: Date,
  lastActive: Date
});

// Track last active
userSchema.pre("save", function (next) {
  this.lastActive = new Date();
  next();
});

userSchema.methods.updateLogin = function () {
  this.lastLogin = new Date();
  return this.save();
};

userSchema.methods.updateLogout = function () {
  this.lastLogout = new Date();
  return this.save();
};

export default mongoose.model("User", userSchema);