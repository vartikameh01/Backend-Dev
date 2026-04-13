import Product from "../models/Product.js";

export const searchProducts = async (req, res) => {
  let query = req.query.q || "";

  query = query.replace(/[$.]/g, "");

  const products = await Product.find({
    name: { $regex: query, $options: "i" }
  });

  res.json(products);
};
