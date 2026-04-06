const todos = [];
// CREATE: Add a new todo
function addTodo(id, title, description) {
  const newTodo = {
    id,
    title,
    description,
    status: "Pending",
  };
  todos.push(newTodo);
  console.log(`Todo added: "${title}"`);
}
// READ:
function displayTodos() {
  if (todos.length === 0) {
    console.log(" No todos found.");
    return;
  }

  console.log("\n All Todos:");
  console.log("─".repeat(50));

  todos.forEach((todo) => {
    console.log(`ID          : ${todo.id}`);
    console.log(`Title       : ${todo.title}`);
    console.log(`Description : ${todo.description}`);
    console.log(`Status      : ${todo.status}`);
    console.log("─".repeat(50));
  });
}
// UPDATE:
function updateTodo(id, updatedFields) {
  const todo = todos.find((t) => t.id === id);

  if (!todo) {
    console.log(`Todo with ID ${id} not found.`);
    return;
  }

  if (updatedFields.title !== undefined) {
    todo.title = updatedFields.title;
  }

  if (updatedFields.description !== undefined) {
    todo.description = updatedFields.description;
  }

  console.log(`  Todo ID ${id} updated successfully.`);
}
function markAsCompleted(id) {
  const todo = todos.find((t) => t.id === id);

  if (!todo) {
    console.log(` Todo with ID ${id} not found.`);
    return;
  }

  if (todo.status === "Completed") {
    console.log(`Todo ID ${id} is already marked as Completed.`);
    return;
  }

  todo.status = "Completed";
  console.log(`Todo ID ${id} marked as Completed.`);
}
// DELETE:
function deleteTodo(id) {
  const index = todos.findIndex((t) => t.id === id);

  if (index === -1) {
    console.log(`Todo with ID ${id} not found.`);
    return;
  }

  const removed = todos.splice(index, 1);
  console.log(`Todo "${removed[0].title}" deleted successfully.`);
}
// Add todos
addTodo(1, "Buy Groceries", "Milk, Eggs, Bread, Butter");
addTodo(2, "Morning Exercise", "30 minutes jogging in the park");
addTodo(3, "Read a Book", "Finish reading Atomic Habits");

// Display all todos
displayTodos();

// Update a todo
updateTodo(2, { title: "Morning Workout", description: "45 minutes gym session" });

// Mark a todo as completed
markAsCompleted(1);

// Display after updates
displayTodos();

// Delete a todo
deleteTodo(3);

// Final display
displayTodos();