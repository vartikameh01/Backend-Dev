//assignment
// app.js
const express = require('express');
const app = express();

app.use(express.json());

// --------------------
// In-memory data store
// --------------------
let books = [
  { id: 1, title: 'The Great Gatsby', author: 'F. Scott Fitzgerald', year: 1925 },
  { id: 2, title: '1984', author: 'George Orwell', year: 1949 },
  { id: 3, title: 'To Kill a Mockingbird', author: 'Harper Lee', year: 1960 },
  { id: 4, title: 'Pride and Prejudice', author: 'Jane Austen', year: 1913 },
  { id: 5, title: 'The Catcher in the Rye', author: 'J.D. Salinger', year: 1951 },
  { id: 6, title: 'Brave New World', author: 'Aldous Huxley', year: 1932 },
  { id: 7, title: 'The Hobbit', author: 'J.R.R. Tolkien', year: 1937 },
  { id: 8, title: 'Fahrenheit 451', author: 'Ray Bradbury', year: 1953 },
  { id: 9, title: 'Animal Farm', author: 'George Orwell', year: 1945 },
  { id: 10, title: 'Lord of the Flies', author: 'William Golding', year: 1954 },
  { id: 11, title: 'The Lord of the Rings', author: 'J.R.R. Tolkien', year: 1954 },
  { id: 12, title: 'One Hundred Years of Solitude', author: 'Gabriel Garcia Marquez', year: 1967 },
  { id: 13, title: 'The Old Man and the Sea', author: 'Ernest Hemingway', year: 1952 },
  { id: 14, title: 'A Farewell to Arms', author: 'Ernest Hemingway', year: 1929 },
  { id: 15, title: 'Slaughterhouse-Five', author: 'Kurt Vonnegut', year: 1969 }
];

let authors = [
  { id: 1, name: 'F. Scott Fitzgerald' },
  { id: 2, name: 'George Orwell' },
  { id: 3, name: 'Harper Lee' },
  { id: 4, name: 'Jane Austen' },
  { id: 5, name: 'J.D. Salinger' },
  { id: 6, name: 'Aldous Huxley' },
  { id: 7, name: 'J.R.R. Tolkien' },
  { id: 8, name: 'Ray Bradbury' },
  { id: 9, name: 'William Golding' },
  { id: 10, name: 'Gabriel Garcia Marquez' },
  { id: 11, name: 'Ernest Hemingway' },
  { id: 12, name: 'Kurt Vonnegut' }
];

let nextBookId = 16;
let nextAuthorId = 13;

// --------------------
// Middleware
// --------------------

// Exercise 2: Validation middleware
const validateBook = (req, res, next) => {
  const { title, author, year } = req.body;

  if (!title || !author || year === undefined) {
    return res.status(400).json({ error: 'Title, author, and year are required' });
  }

  const parsedYear = Number(year);

  if (Number.isNaN(parsedYear)) {
    return res.status(400).json({ error: 'Year must be a valid number' });
  }

  if (parsedYear < 1900 || parsedYear > new Date().getFullYear()) {
    return res.status(400).json({ error: 'Year must be within a reasonable range' });
  }

  req.body.year = parsedYear;
  next();
};

// --------------------
// BOOK ROUTES
// --------------------

// CREATE
app.post('/api/books', validateBook, (req, res) => {
  const { title, author, year } = req.body;

  const newBook = { id: nextBookId++, title, author, year };
  books.push(newBook);

  res.status(201).json(newBook);
});

// READ (all)
// Exercise 1: Filtering
// Exercise 3: Pagination
// Exercise 5: Search by title
app.get('/api/books', (req, res) => {
  let result = [...books];

  const { author, year, search, page = 1, limit = 10 } = req.query;

  // Filtering (Exercise 1)
  if (author) {
    result = result.filter(b =>
      b.author.toLowerCase().includes(author.toLowerCase())
    );
  }

  if (year) {
    result = result.filter(b => b.year === Number(year));
  }

  // Search by title (Exercise 5)
  if (search) {
    result = result.filter(b =>
      b.title.toLowerCase().includes(search.toLowerCase())
    );
  }

  // Pagination (Exercise 3)
  const parsedPage = Number(page);
  const parsedLimit = Number(limit);

  const startIndex = (parsedPage - 1) * parsedLimit;
  const endIndex = startIndex + parsedLimit;

  const paginated = result.slice(startIndex, endIndex);

  res.json({
    total: result.length,
    page: parsedPage,
    limit: parsedLimit,
    data: paginated
  });
});

// READ (one)
app.get('/api/books/:id', (req, res) => {
  const id = Number(req.params.id);
  const book = books.find(b => b.id === id);

  if (!book) {
    return res.status(404).json({ error: 'Book not found' });
  }

  res.json(book);
});

// UPDATE (PUT)
app.put('/api/books/:id', validateBook, (req, res) => {
  const id = Number(req.params.id);
  const index = books.findIndex(b => b.id === id);

  if (index === -1) {
    return res.status(404).json({ error: 'Book not found' });
  }

  const { title, author, year } = req.body;
  books[index] = { id, title, author, year };

  res.json(books[index]);
});

// UPDATE (PATCH)
app.patch('/api/books/:id', (req, res) => {
  const id = Number(req.params.id);
  const index = books.findIndex(b => b.id === id);

  if (index === -1) {
    return res.status(404).json({ error: 'Book not found' });
  }

  const { title, author, year } = req.body;

  if (year !== undefined) {
    const parsedYear = Number(year);

    if (Number.isNaN(parsedYear)) {
      return res.status(400).json({ error: 'Year must be a valid number' });
    }

    if (parsedYear < 0 || parsedYear > new Date().getFullYear()) {
      return res.status(400).json({ error: 'Year must be within a reasonable range' });
    }

    books[index].year = parsedYear;
  }

  if (title) books[index].title = title;
  if (author) books[index].author = author;

  res.json(books[index]);
});

// DELETE
app.delete('/api/books/:id', (req, res) => {
  const id = Number(req.params.id);
  const index = books.findIndex(b => b.id === id);

  if (index === -1) {
    return res.status(404).json({ error: 'Book not found' });
  }

  const deleted = books.splice(index, 1)[0];

  res.json({
    message: 'Book deleted successfully',
    book: deleted
  });
});

// --------------------
// AUTHOR ROUTES
// --------------------
// Exercise 4: New resource CRUD

// CREATE
app.post('/api/authors', (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Author name is required' });
  }

  const newAuthor = { id: nextAuthorId++, name };
  authors.push(newAuthor);

  res.status(201).json(newAuthor);
});

// READ (all)
app.get('/api/authors', (req, res) => {
  res.json(authors);
});

// READ (one)
app.get('/api/authors/:id', (req, res) => {
  const id = Number(req.params.id);
  const author = authors.find(a => a.id === id);

  if (!author) {
    return res.status(404).json({ error: 'Author not found' });
  }

  res.json(author);
});

// UPDATE
app.put('/api/authors/:id', (req, res) => {
  const id = Number(req.params.id);
  const index = authors.findIndex(a => a.id === id);

  if (index === -1) {
    return res.status(404).json({ error: 'Author not found' });
  }

  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Author name is required' });
  }

  authors[index] = { id, name };

  res.json(authors[index]);
});

// DELETE
app.delete('/api/authors/:id', (req, res) => {
  const id = Number(req.params.id);
  const index = authors.findIndex(a => a.id === id);

  if (index === -1) {
    return res.status(404).json({ error: 'Author not found' });
  }

  const deleted = authors.splice(index, 1)[0];

  res.json({
    message: 'Author deleted successfully',
    author: deleted
  });
});

// --------------------
// Error Handling
// --------------------
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// --------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

