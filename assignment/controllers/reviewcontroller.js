import xss from "xss";
import Review from "../models/Review.js";

export const addReview = async (req, res) => {
  const clean = xss(req.body.text);

  const review = await Review.create({
    text: clean,
    user: req.session.user._id
  });

  res.json(review);
};
