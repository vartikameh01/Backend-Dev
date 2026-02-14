const express = require("express");
const path = require("path");
const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));

// Serve static files (images, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// Set EJS view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Hardcoded users
let users = [
    { id: 1, name: "Mahak" },
    { id: 2, name: "doll" },
    { id: 3, name: "duggu" },
    { id: 4, name: "amu" }
];

// Hardcoded blog posts
let posts = [
    { id: 1, title: "First Post", content: "This is my first blog post" },
    { id: 2, title: "Second Post", content: "This is my second blog post" }
];

// HOME -> redirect to /users
app.get("/", (req, res) => {
    res.redirect("/users");
});

// USERS PAGE
app.get("/users", (req, res) => {
    const search = req.query.name;
    let filteredUsers = users;

    if (search) {
        filteredUsers = users.filter(u =>
            u.name.toLowerCase().includes(search.toLowerCase())
        );
    }
    res.render("users", { users: filteredUsers });
});

// CONTACT PAGE
app.get("/contact", (req, res) => {
    res.render("contact");
});

app.post("/contact", (req, res) => {
    console.log("Contact Form Submitted:", req.body);
    res.send("Contact form submitted successfully!");
});

// GALLERY PAGE
app.get("/gallery", (req, res) => {
    // List of images stored in /public/images
    const images = [
        "img1.jpg",
        "img2.jpg",
        "WhatsApp Image 2026-02-09 at 10.32.00 AM.jpeg"
    ];
    res.render("gallery", { images });
});

// BLOG PAGE
app.get("/blog", (req, res) => {
    res.render("blog", { posts });
});

// NEW POST FORM
app.get("/new-post", (req, res) => {
    res.render("new-post");
});

// CREATE POST
app.post("/new-post", (req, res) => {
    const { title, content } = req.body;
    posts.push({
        id: posts.length + 1,
        title,
        content
    });
    res.redirect("/blog");
});

// SINGLE POST VIEW
app.get("/post/:id", (req, res) => {
    const post = posts.find(p => p.id == req.params.id);
    if (!post) return res.render("404");
    res.render("post", { post });
});

// 404 PAGE
app.use((req, res) => {
    res.status(404).render("404");
});

// SERVER
app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
});