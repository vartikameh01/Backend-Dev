import sanitizeHtml from "sanitize-html";

export const cleanHTML = (content) => {
  return sanitizeHtml(content, {
    allowedTags: ["b", "i", "a"],
    allowedAttributes: {
      a: ["href"]
    }
  });
};