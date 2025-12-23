// server.js - Backend Server with SQLite Database
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static HTML files

// Initialize SQLite Database
const db = new sqlite3.Database('./anime_x.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        createTable();
    }
});

// Create users table
function createTable() {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            date_of_birth TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('Error creating table:', err);
        } else {
            console.log('Users table ready');
        }
    });
}

// Sign In endpoint - Register new user
app.post('/api/signin', async (req, res) => {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Username and password are required' 
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

        // Insert user into database
        db.run(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(409).json({ 
                            success: false, 
                            message: 'Username already exists' 
                        });
                    }
                    return res.status(500).json({ 
                        success: false, 
                        message: 'Database error' 
                    });
                }

                res.json({ 
                    success: true, 
                    message: 'User registered successfully',
                    userId: this.lastID
                });
            }
        );
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Login endpoint - Authenticate user
app.post('/api/login', (req, res) => {
    const { email, dateOfBirth } = req.body;

    // Validation
    if (!email || !dateOfBirth) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email and date of birth are required' 
        });
    }

    // Find user by email and date of birth
    db.get(
        'SELECT * FROM users WHERE email = ? AND date_of_birth = ?',
        [email, dateOfBirth],
        (err, user) => {
            if (err) {
                return res.status(500).json({ 
                    success: false, 
                    message: 'Database error' 
                });
            }

            if (!user) {
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid email or date of birth' 
                });
            }

            res.json({ 
                success: true, 
                message: 'Login successful',
                username: user.username
            });
        }
    );
});

// Update user profile endpoint
app.post('/api/update-profile', (req, res) => {
    const { username, email, dateOfBirth } = req.body;

    if (!username) {
        return res.status(400).json({ 
            success: false, 
            message: 'Username is required' 
        });
    }

    db.run(
        'UPDATE users SET email = ?, date_of_birth = ? WHERE username = ?',
        [email, dateOfBirth, username],
        function(err) {
            if (err) {
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

// Get user info endpoint
app.get('/api/user/:username', (req, res) => {
    const username = req.params.username;

    db.get(
        'SELECT username, email, date_of_birth, created_at FROM users WHERE username = ?',
        [username],
        (err, user) => {
            if (err) {
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
                user: user 
            });
        }
    );
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed');
        }
        process.exit(0);
    });
});