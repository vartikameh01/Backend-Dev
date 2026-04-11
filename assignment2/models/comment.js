import mongoose from "mongoose";

const commentSchema = new mongoose.Schema({
  text: String,
  postId: String
});

export default mongoose.model("Comment", commentSchema);