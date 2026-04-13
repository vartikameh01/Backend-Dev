import Post from "../models/post.js";
import { cleanHTML } from "../utils/sanitizehtml.js";

export const createPost = async (req, res) => {
  const content = cleanHTML(req.body.content);

  const post = await Post.create({
    content,
    user: req.session.user._id
  });

  res.json(post);
};