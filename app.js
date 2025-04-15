const express = require('express');
const bcrypt = require('bcryptjs');
const app = express();
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

// Use cookie-parser middleware to read cookies
app.use(cookieParser());

// Set up the SQLite database
const db = new sqlite3.Database('./users.db');

// Secret key for signing JWT
const JWT_SECRET_KEY = 'your-secret-key';

// Create users table if it doesn't exist
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Ensure 'views' folder exists
app.use(express.urlencoded({ extended: true }));

// Route to show the login page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Route to handle login form submission
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        if (user && bcrypt.compareSync(password, user.password)) {
            // Generate JWT token upon successful login
            const token = jwt.sign({ username: user.username }, JWT_SECRET_KEY, { expiresIn: '10s' }); // Expires in 10 seconds

            // Set the token in a cookie
            res.cookie('auth_token', token, { httpOnly: true, secure: false });  // `secure: true` for HTTPS
            res.redirect('/dashboard');
        } else {
            res.render('login', { error: 'Invalid credentials' });
        }
    });
});


// Route to show the create user page
app.get('/create-user', (req, res) => {
    res.render('createUser', { error: null });
});

// Route to handle create user form submission
app.post('/create-user', (req, res) => {
    const { username, password } = req.body;

    // Check if username already exists
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        if (user) {
            return res.render('createUser', { error: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = bcrypt.hashSync(password, 10);

        // Insert the new user into the database
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function (err) {
            if (err) {
                return res.status(500).send('Error creating user');
            }

            // Redirect to the login page after successful registration
            res.redirect('/login');
        });
    });
});

app.get('/dashboard', (req, res) => {
    const token = req.cookies.auth_token; // Retrieve JWT from cookies
    console.log('JWT Token:', token);

    if (!token) {
        console.log('No token found. Redirecting to login.');
        return res.redirect('/login'); // If no token, redirect to login page
    }

    // Verify and decode JWT
    jwt.verify(token, JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            console.log('Invalid token:', err.message);
            return res.redirect('/login'); // If token is invalid, redirect to login
        }

        console.log('Decoded JWT:', decoded);
        // Pass the decoded token to the EJS template
        res.render('dashboard', { user: decoded, token: token, decoded: decoded });
    });
});


// Route to handle logout
app.get('/logout', (req, res) => {
    res.clearCookie('auth_token'); // Clear the cookie
    res.redirect('/login'); // Redirect to login page
});


app.listen(3901, () => {
    console.log('Server running on port 3901');
});
