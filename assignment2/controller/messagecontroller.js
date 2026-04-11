import Message from "../models/message.js";
import xss from "xss";

export const sendMessage = async (req, res) => {
  const cleanMsg = xss(req.body.message);

  const msg = await Message.create({
    sender: req.session.user._id,
    receiver: req.body.receiver,
    message: cleanMsg
  });

  res.json(msg);
};