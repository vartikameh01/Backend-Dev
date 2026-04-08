import mongoose from "mongoose";

const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  isDeleted: {
    type: Boolean,
    default: false
  }
});

// Filter deleted automatically
productSchema.pre(/^find/, function (next) {
  this.where({ isDeleted: false });
  next();
});

// Soft delete method
productSchema.methods.softDelete = function () {
  this.isDeleted = true;
  return this.save();
};

export default mongoose.model("Product", productSchema);