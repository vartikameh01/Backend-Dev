const express = require("express");
const path = require("path");
const { readEmployees, writeEmployees } = require("./modules/fileHandler");

const app = express();
const PORT = 3000;

// Middleware
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));



// Dashboard - Show all employees
app.get("/", async (req, res) => {
  const employees = await readEmployees();
  res.render("index", { employees });
});

// Add Employee - Show form
app.get("/add", (req, res) => {
  res.render("add");
});

// Add Employee - Handle form submission
app.post("/add", async (req, res) => {
  const { name, department, salary } = req.body;

  // Validation
  if (!name || !name.trim()) {
    return res.redirect("/add");
  }
  if (!salary || Number(salary) < 0) {
    return res.redirect("/add");
  }

  const employees = await readEmployees();

  const newEmployee = {
    id: Date.now(),
    name: name.trim(),
    department: department ? department.trim() : "",
    salary: Number(salary),
  };

  employees.push(newEmployee);
  await writeEmployees(employees);
  res.redirect("/");
});

// Edit Employee - Show form
app.get("/edit/:id", async (req, res) => {
  const employees = await readEmployees();
  const employee = employees.find((e) => e.id === Number(req.params.id));

  if (!employee) {
    return res.redirect("/");
  }

  res.render("edit", { employee });
});

// Edit Employee - Handle form submission
app.post("/edit/:id", async (req, res) => {
  const { name, department, salary } = req.body;

  // Validation
  if (!name || !name.trim()) {
    return res.redirect("/edit/" + req.params.id);
  }
  if (!salary || Number(salary) < 0) {
    return res.redirect("/edit/" + req.params.id);
  }

  const employees = await readEmployees();
  const index = employees.findIndex((e) => e.id === Number(req.params.id));

  if (index === -1) {
    return res.redirect("/");
  }

  employees[index].name = name.trim();
  employees[index].department = department ? department.trim() : "";
  employees[index].salary = Number(salary);

  await writeEmployees(employees);
  res.redirect("/");
});

// Delete Employee
app.get("/delete/:id", async (req, res) => {
  const employees = await readEmployees();
  const filtered = employees.filter((e) => e.id !== Number(req.params.id));
  await writeEmployees(filtered);
  res.redirect("/");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
