import jwt from "jsonwebtoken";

const mfa = (req, res, next) => {
  const token = req.headers.authorization;
  const otp = req.headers["x-otp"];

  if (!token || !otp) {
    return res.status(401).send("Token & OTP required");
  }

  try {
    const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);

    if (otp !== "123456") {
      return res.status(401).send("Invalid OTP");
    }

    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Invalid Token");
  }
};

export default mfa;