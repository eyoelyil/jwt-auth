const sqlite3 = require('sqlite3').verbose();

// Create and connect to SQLite database
const db = new sqlite3.Database('./database.db');

// Create the users table if it doesn't exist
db.serialize(() => {
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `);
});

// Function to export the database instance
module.exports = { db };
