import validator from "validator";

export const validateRegister = (req, res, next) => {
  const { username, email } = req.body;

  if (!validator.isAlphanumeric(username)) {
    return res.status(400).send("Invalid username");
  }

  if (!validator.isEmail(email)) {
    return res.status(400).send("Invalid email");
  }

  next();
};