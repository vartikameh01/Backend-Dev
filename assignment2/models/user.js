import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  bio: String,
  profileUrl: String
});

export default mongoose.model("User", userSchema);