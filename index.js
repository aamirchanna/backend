const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = 'your_university_project_secret_key';

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

// --- AUTH ENDPOINTS ---

app.post('/api/auth/register', async (req, res) => {
  const { email, password, user_type } = req.body;
  
  // Validation
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be 6+ chars' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, user_type) VALUES ($1, $2, $3) RETURNING id, email, user_type',
      [email, hashedPassword, user_type]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'User already exists or database error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, user_type: user.user_type }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, user_type: user.user_type } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/auth/profile/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { password } = req.body;
    if (req.user.id != id) return res.status(403).json({ error: 'Unauthorized' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [hashedPassword, id]);
        res.json({ message: 'Password updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- BOOK ENDPOINTS ---

app.get('/api/books', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM books WHERE quantity > 0 ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/books', authenticateToken, async (req, res) => {
  if (req.user.user_type !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { name, author, description, cover_url, condition, condition_notes, quantity, rental_price_per_day, purchase_price, isbn } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO books (name, author, description, cover_url, condition, condition_notes, quantity, rental_price_per_day, purchase_price, isbn) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
      [name, author, description, cover_url, condition, condition_notes, quantity, rental_price_per_day, purchase_price, isbn]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/books/:id', authenticateToken, async (req, res) => {
    if (req.user.user_type !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { id } = req.params;
    const { name, author, description, cover_url, condition, condition_notes, quantity, rental_price_per_day, purchase_price, isbn } = req.body;
    try {
        const result = await pool.query(
            'UPDATE books SET name=$1, author=$2, description=$3, cover_url=$4, condition=$5, condition_notes=$6, quantity=$7, rental_price_per_day=$8, purchase_price=$9, isbn=$10 WHERE id=$11 RETURNING *',
            [name, author, description, cover_url, condition, condition_notes, quantity, rental_price_per_day, purchase_price, isbn, id]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- TRANSACTION ENDPOINTS ---

app.post('/api/transactions/rent', authenticateToken, async (req, res) => {
    const { book_id, days_rented, total_price } = req.body;
    const user_id = req.user.id;
    try {
        await pool.query('BEGIN');
        const bookRes = await pool.query('SELECT quantity FROM books WHERE id = $1', [book_id]);
        if (bookRes.rows[0].quantity <= 0) throw new Error('Out of stock');

        const result = await pool.query(
            'INSERT INTO transactions (user_id, book_id, transaction_type, days_rented, total_price) VALUES ($1, $2, \'rent\', $3, $4) RETURNING *',
            [user_id, book_id, days_rented, total_price]
        );
        await pool.query('UPDATE books SET quantity = quantity - 1 WHERE id = $1', [book_id]);
        await pool.query('COMMIT');
        res.status(201).json(result.rows[0]);
    } catch (err) {
        await pool.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/transactions/buy', authenticateToken, async (req, res) => {
    const { book_id, total_price } = req.body;
    const user_id = req.user.id;
    try {
        await pool.query('BEGIN');
        const result = await pool.query(
            'INSERT INTO transactions (user_id, book_id, transaction_type, total_price) VALUES ($1, $2, \'buy\', $3) RETURNING *',
            [user_id, book_id, total_price]
        );
        await pool.query('UPDATE books SET quantity = quantity - 1 WHERE id = $1', [book_id]);
        await pool.query('COMMIT');
        res.status(201).json(result.rows[0]);
    } catch (err) {
        await pool.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    }
});

// Return Book (Admin only)
app.post('/api/transactions/return/:transactionId', authenticateToken, async (req, res) => {
    if (req.user.user_type !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { transactionId } = req.params;
    try {
        await pool.query('BEGIN');
        const trans = await pool.query('SELECT book_id, transaction_type FROM transactions WHERE id = $1', [transactionId]);
        if (trans.rows.length === 0) throw new Error('Transaction not found');
        
        const bookId = trans.rows[0].book_id;
        // Increase quantity
        await pool.query('UPDATE books SET quantity = quantity + 1 WHERE id = $1', [bookId]);
        // Delete transaction or mark as returned (deleting for simplicity in this project)
        await pool.query('DELETE FROM transactions WHERE id = $1', [transactionId]);
        
        await pool.query('COMMIT');
        res.json({ message: 'Book returned successfully' });
    } catch (err) {
        await pool.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/transactions', authenticateToken, async (req, res) => {
    if (req.user.user_type !== 'admin') return res.status(403).json({ error: 'Admin only' });
    try {
        const result = await pool.query(
            'SELECT t.*, b.name as book_name, u.email FROM transactions t JOIN books b ON t.book_id = b.id JOIN users u ON t.user_id = u.id ORDER BY t.transaction_date DESC'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/transactions/:userId', authenticateToken, async (req, res) => {
    if (req.user.id != req.params.userId) return res.status(403).json({ error: 'Unauthorized' });
    try {
        const result = await pool.query(
            'SELECT t.*, b.name as book_name, b.cover_url FROM transactions t JOIN books b ON t.book_id = b.id WHERE t.user_id = $1 ORDER BY t.transaction_date DESC',
            [req.params.userId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/reminders/:userId', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT t.*, b.name as book_name, 
            (t.transaction_date + (t.days_rented || ' days')::interval) as due_date,
            EXTRACT(DAY FROM (t.transaction_date + (t.days_rented || ' days')::interval) - CURRENT_TIMESTAMP) as days_left
            FROM transactions t/ 
            JOIN books b ON t.book_id = b.id 
            WHERE t.user_id = $1 AND t.transaction_type = 'rent'
            ORDER BY due_date ASC`,
            [req.params.userId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));  