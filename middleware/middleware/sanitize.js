const sanitize = (req, res, next) => {
  const clean = (obj) => {
    if (!obj) return obj;

    for (let key in obj) {
      if (typeof obj[key] === "string") {
        // Remove script tags
        obj[key] = obj[key].replace(/<script.*?>.*?<\/script>/gi, "");

        // Remove Mongo operators ($, .)
        obj[key] = obj[key].replace(/\$/g, "").replace(/\./g, "");
      } else if (typeof obj[key] === "object") {
        clean(obj[key]);
      }
    }
    return obj;
  };

  req.body = clean(req.body);
  req.params = clean(req.params);

  next();
};

export default sanitize;