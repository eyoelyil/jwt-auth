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

// Middleware to authenticate token
function authenticateToken(req, res, next) {
    const token = req.cookies.auth_token;

    if (!token) {
        return res.redirect('/login'); // Redirect to login if no token is found
    }

    jwt.verify(token, JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.redirect('/login'); // Redirect to login if the token is invalid
        }

        // Attach the decoded token to the request object
        req.user = decoded;
        next();
    });
}

// Sliding expiration middleware
app.use((req, res, next) => {
    const token = req.cookies.auth_token;

    if (token) {
        jwt.verify(token, JWT_SECRET_KEY, (err, decoded) => {
            if (!err) {
                const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
                const remainingTime = decoded.exp - currentTime; // Remaining time on the token

                // Ensure the remaining time is positive
                if (remainingTime > 0) {
                    const newExpirationTime = remainingTime + 5; // Add 5 seconds to the remaining time

                    // Generate a new token with the updated expiration time
                    const newToken = jwt.sign({ username: decoded.username }, JWT_SECRET_KEY, { expiresIn: newExpirationTime });
                    res.cookie('auth_token', newToken, { httpOnly: true, secure: false });
                }
            }
        });
    }

    next();
});

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
            res.cookie('auth_token', token, { httpOnly: true, secure: false }); // `secure: true` for HTTPS
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

// Route to show the dashboard page
app.get('/dashboard', authenticateToken, (req, res) => {
    const token = req.cookies.auth_token; // Retrieve the token from cookies

    jwt.verify(token, JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.redirect('/login'); // Redirect to login if the token is invalid
        }

        // Pass the decoded token and other data to the EJS template
        res.render('dashboard', { user: req.user, token: token, decoded: decoded });
    });
});

// Refresh token route
app.post('/refresh-token', authenticateToken, (req, res) => {
    const newToken = jwt.sign({ username: req.user.username }, JWT_SECRET_KEY, { expiresIn: '10s' });

    // Set the new token in a cookie
    res.cookie('auth_token', newToken, { httpOnly: true, secure: false });
    res.send('Token refreshed');
});

// Route to handle logout
app.get('/logout', (req, res) => {
    res.clearCookie('auth_token'); // Clear the cookie
    res.redirect('/login'); // Redirect to login page
});

// Start the server
app.listen(3901, () => {
    console.log('Server running on port 3901');
});