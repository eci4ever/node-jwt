const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const conn = require('./conn.js');

const router = express.Router();

router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const [rows] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);

        if (rows.length) {
            return res.status(409).json({ error: 'Email already exists.' });
        }

        const hash = await bcrypt.hash(password, 10);

        await conn.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hash]);

        res.status(201).json({ message: 'User register successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [rows] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);

        if (!rows.length) {
            return res.status(401).json({ error: 'Email or password is incorrect.' });
        }

        const user = rows[0];

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ error: 'Email or password is incorrect.' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// function to verify token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ error: 'A token is required for authentication.' });
    }

    try {
        const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
        req.user = decoded;
    } catch (err) {
        return res.status(401).json({ error: 'Invalid Token' });
    }

    return next();
}

router.get('/users', async (req, res) => {
    try {
        const [rows] = await conn.query('SELECT * FROM users');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// get user by id
router.get('/users/:id', verifyToken, async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await conn.query('SELECT * FROM users WHERE id = ?', [id]);

        if (!rows.length) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
