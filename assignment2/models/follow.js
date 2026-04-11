import mongoose from "mongoose";

const followSchema = new mongoose.Schema({
  follower: String,
  following: String
});

export default mongoose.model("Follow", followSchema);