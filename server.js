const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const diskPath = process.env.RENDER_DISK_PATH || '.';
const dbPath = path.join(diskPath, 'penpals.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to SQLite database.');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      country TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      payment_status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      tx_ref TEXT UNIQUE NOT NULL,
      amount REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      paid_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.post('/api/register', async (req, res) => {
  const { full_name, email, country, password } = req.body;
  if (!full_name || !email || !country || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (row) return res.status(409).json({ error: 'Email already registered' });
      const password_hash = await bcrypt.hash(password, 10);
      db.run(
        'INSERT INTO users (full_name, email, country, password_hash) VALUES (?, ?, ?, ?)',
        [full_name, email, country, password_hash],
        function (err) {
          if (err) return res.status(500).json({ error: 'Registration failed' });
          res.status(201).json({ message: 'Registration successful. Please login and complete payment.', user_id: this.lastID });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user.id, email: user.email, payment_status: user.payment_status },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        country: user.country,
        payment_status: user.payment_status
      }
    });
  });
});

app.post('/api/payment/initialize', authenticateToken, async (req, res) => {
  const user_id = req.user.id;
  const amount = parseInt(process.env.AMOUNT) || 50000;
  const currency = process.env.CURRENCY || 'UGX';
  const tx_ref = `UPP_${Date.now()}_${user_id}`;
  try {
    const response = await axios.post(
      'https://api.flutterwave.com/v3/payments',
      {
        tx_ref,
        amount,
        currency,
        redirect_url: `${process.env.BACKEND_URL}/api/payment/verify`,
        customer: { email: req.user.email },
        customizations: {
          title: 'Universal Pen Pals Membership',
          description: 'Membership fee for Universal Pen Pals',
        },
        payment_options: 'card,mobilemoneyuganda,mpesa,banktransfer,ussd',
        meta: { user_id }
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );
    db.run(
      'INSERT INTO payments (user_id, tx_ref, amount, status) VALUES (?, ?, ?, ?)',
      [user_id, tx_ref, amount, 'pending'],
      (err) => { if (err) console.error('Failed to save payment:', err); }
    );
    res.json({ authorization_url: response.data.data.link, tx_ref });
  } catch (error) {
    console.error('Flutterwave init error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Payment initialization failed' });
  }
});

app.get('/api/payment/verify', async (req, res) => {
  const { tx_ref, transaction_id } = req.query;
  if (!tx_ref) return res.status(400).send('Missing transaction reference');
  try {
    const response = await axios.get(
      `https://api.flutterwave.com/v3/transactions/${transaction_id}/verify`,
      {
        headers: { Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}` }
      }
    );
    const data = response.data.data;
    if (data.status === 'successful' && data.tx_ref === tx_ref) {
      db.run('UPDATE payments SET status = ?, paid_at = CURRENT_TIMESTAMP WHERE tx_ref = ?', ['success', tx_ref]);
      db.get('SELECT user_id FROM payments WHERE tx_ref = ?', [tx_ref], (err, row) => {
        if (row) db.run('UPDATE users SET payment_status = ? WHERE id = ?', ['paid', row.user_id]);
      });
      res.redirect(`${process.env.FRONTEND_URL}/?payment=success`);
    } else {
      res.redirect(`${process.env.FRONTEND_URL}/?payment=failed`);
    }
  } catch (error) {
    console.error('Flutterwave verify error:', error.response?.data || error.message);
    res.redirect(`${process.env.FRONTEND_URL}/?payment=error`);
  }
});

app.get('/api/profile', authenticateToken, (req, res) => {
  db.get('SELECT id, full_name, email, country, payment_status, created_at FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

app.get('/api/config', (req, res) => {
  res.json({
    amount: parseInt(process.env.AMOUNT) || 50000,
    currency: process.env.CURRENCY || 'UGX'
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
