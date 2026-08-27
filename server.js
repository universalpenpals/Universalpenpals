const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { createClient } = require('@libsql/client');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Connect to Turso (cloud SQLite)
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Create tables
async function initDB() {
  try {
    await db.execute(`
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
    await db.execute(`
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
    console.log('✅ Turso database connected and tables ready');
  } catch (err) {
    console.error('❌ Database init error:', err);
  }
}
initDB();

// Authenticate JWT
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

// Helper: Get user by email
async function getUserByEmail(email) {
  const result = await db.execute({
    sql: 'SELECT * FROM users WHERE email = ?',
    args: [email],
  });
  return result.rows[0];
}

// Helper: Get user by ID
async function getUserById(id) {
  const result = await db.execute({
    sql: 'SELECT id, full_name, email, country, payment_status, created_at FROM users WHERE id = ?',
    args: [id],
  });
  return result.rows[0];
}

// Register endpoint
app.post('/api/register', async (req, res) => {
  const { full_name, email, country, password } = req.body;
  if (!full_name || !email || !country || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const existing = await getUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const result = await db.execute({
      sql: 'INSERT INTO users (full_name, email, country, password_hash) VALUES (?, ?, ?, ?)',
      args: [full_name, email, country, password_hash],
    });
    res.status(201).json({
      message: 'Registration successful. Please login and complete payment.',
      user_id: result.lastInsertRowid,
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  try {
    const user = await getUserByEmail(email);
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
        payment_status: user.payment_status,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize payment
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
        meta: { user_id },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );
    await db.execute({
      sql: 'INSERT INTO payments (user_id, tx_ref, amount, status) VALUES (?, ?, ?, ?)',
      args: [user_id, tx_ref, amount, 'pending'],
    });
    res.json({ authorization_url: response.data.data.link, tx_ref });
  } catch (error) {
    console.error('Flutterwave init error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Payment initialization failed' });
  }
});

// Verify payment
app.get('/api/payment/verify', async (req, res) => {
  const { tx_ref, transaction_id } = req.query;
  if (!tx_ref) return res.status(400).send('Missing transaction reference');
  try {
    const response = await axios.get(
      `https://api.flutterwave.com/v3/transactions/${transaction_id}/verify`,
      {
        headers: { Authorization: `Bearer ${process.env.FLUTTERWAVE_SECRET_KEY}` },
      }
    );
    const data = response.data.data;
    if (data.status === 'successful' && data.tx_ref === tx_ref) {
      await db.execute({
        sql: 'UPDATE payments SET status = ?, paid_at = CURRENT_TIMESTAMP WHERE tx_ref = ?',
        args: ['success', tx_ref],
      });
      const result = await db.execute({
        sql: 'SELECT user_id FROM payments WHERE tx_ref = ?',
        args: [tx_ref],
      });
      if (result.rows.length > 0) {
        const user_id = result.rows[0].user_id;
        await db.execute({
          sql: 'UPDATE users SET payment_status = ? WHERE id = ?',
          args: ['paid', user_id],
        });
      }
      res.redirect(`${process.env.FRONTEND_URL}/?payment=success`);
    } else {
      res.redirect(`${process.env.FRONTEND_URL}/?payment=failed`);
    }
  } catch (error) {
    console.error('Flutterwave verify error:', error.response?.data || error.message);
    res.redirect(`${process.env.FRONTEND_URL}/?payment=error`);
  }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Get config (for frontend)
app.get('/api/config', (req, res) => {
  res.json({
    amount: parseInt(process.env.AMOUNT) || 50000,
    currency: process.env.CURRENCY || 'UGX',
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
