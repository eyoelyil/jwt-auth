const bcrypt = require('bcryptjs');
const { db } = require('./database');

const username = 'testuser';
const password = 'testpassword';  // This is the password to hash

bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
        console.log('Error hashing password', err);
        return;
    }

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
        if (err) {
            console.log('Error inserting user', err);
            return;
        }
        console.log('User created with ID: ', this.lastID);
    });
});
