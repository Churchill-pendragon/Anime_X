// server.js - Anime X Backend Server with SQLite Database

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===============================
// DATABASE
// ===============================

const db = new sqlite3.Database('./anime_x.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        createTable();
    }
});

function createTable() {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE,
            date_of_birth TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('Error creating users table:', err);
        } else {
            console.log('Users table ready');
        }
    });
}

// ===============================
// REGISTER
// ===============================

app.post('/api/signin', async (req, res) => {
    const {
        username,
        password,
        email,
        dateOfBirth
    } = req.body;

    // Validation
    if (!username || !password || !email || !dateOfBirth) {
        return res.status(400).json({
            success: false,
            message: 'Username, password, email and date of birth are required'
        });
    }

    if (username.length < 3 || username.length > 20) {
        return res.status(400).json({
            success: false,
            message: 'Username must be 3-20 characters'
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            success: false,
            message: 'Password must be at least 6 characters'
        });
    }

    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            `
            INSERT INTO users
            (username, password, email, date_of_birth)
            VALUES (?, ?, ?, ?)
            `,
            [
                username.trim(),
                hashedPassword,
                email.trim().toLowerCase(),
                dateOfBirth
            ],
            function (err) {

                if (err) {
                    console.error('Registration error:', err.message);

                    if (err.message.includes('UNIQUE')) {
                        return res.status(409).json({
                            success: false,
                            message: 'Username or email already exists'
                        });
                    }

                    return res.status(500).json({
                        success: false,
                        message: 'Database error'
                    });
                }

                res.status(201).json({
                    success: true,
                    message: 'User registered successfully',
                    userId: this.lastID,
                    username: username.trim()
                });
            }
        );

    } catch (error) {
        console.error('Password hashing error:', error);

        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ===============================
// LOGIN
// ===============================

app.post('/api/login', (req, res) => {

    const {
        email,
        password
    } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email and password are required'
        });
    }

    db.get(
        `
        SELECT *
        FROM users
        WHERE email = ?
        `,
        [email.trim().toLowerCase()],
        async (err, user) => {

            if (err) {
                console.error('Login database error:', err);

                return res.status(500).json({
                    success: false,
                    message: 'Database error'
                });
            }

            if (!user) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid email or password'
                });
            }

            try {

                const passwordMatch = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!passwordMatch) {
                    return res.status(401).json({
                        success: false,
                        message: 'Invalid email or password'
                    });
                }

                res.json({
                    success: true,
                    message: 'Login successful',
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        dateOfBirth: user.date_of_birth
                    }
                });

            } catch (error) {

                console.error('Password comparison error:', error);

                res.status(500).json({
                    success: false,
                    message: 'Server error'
                });
            }
        }
    );
});

// ===============================
// UPDATE PROFILE
// ===============================

app.post('/api/update-profile', (req, res) => {

    const {
        username,
        email,
        dateOfBirth
    } = req.body;

    if (!username) {
        return res.status(400).json({
            success: false,
            message: 'Username is required'
        });
    }

    db.run(
        `
        UPDATE users
        SET email = ?, date_of_birth = ?
        WHERE username = ?
        `,
        [
            email ? email.trim().toLowerCase() : null,
            dateOfBirth || null,
            username
        ],
        function (err) {

            if (err) {

                if (err.message.includes('UNIQUE')) {
                    return res.status(409).json({
                        success: false,
                        message: 'Email already exists'
                    });
                }

                console.error('Profile update error:', err);

                return res.status(500).json({
                    success: false,
                    message: 'Database error'
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            res.json({
                success: true,
                message: 'Profile updated successfully'
            });
        }
    );
});

// ===============================
// GET USER
// ===============================

app.get('/api/user/:username', (req, res) => {

    const username = req.params.username;

    db.get(
        `
        SELECT
            id,
            username,
            email,
            date_of_birth,
            created_at
        FROM users
        WHERE username = ?
        `,
        [username],
        (err, user) => {

            if (err) {
                console.error('User lookup error:', err);

                return res.status(500).json({
                    success: false,
                    message: 'Database error'
                });
            }

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            res.json({
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    dateOfBirth: user.date_of_birth,
                    createdAt: user.created_at
                }
            });
        }
    );
});

// ===============================
// HEALTH CHECK
// ===============================

app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Anime X server is running'
    });
});

// ===============================
// START SERVER
// ===============================

app.listen(PORT, () => {
    console.log(`Anime X server running on port ${PORT}`);
});

// ===============================
// GRACEFUL SHUTDOWN
// ===============================

process.on('SIGINT', () => {

    db.close((err) => {

        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed');
        }

        process.exit(0);
    });
});        )
