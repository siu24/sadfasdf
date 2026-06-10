import express from 'express';
import pg from 'pg';
import dotenv from 'dotenv';
import path from 'path';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Auth Middleware
const authenticate = async (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const userId = req.cookies.userId;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// --- API Routes ---

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
      [username, hashedPassword]
    );
    res.json({ success: true, userId: result.rows[0].id });
  } catch (err: any) {
    if (err.code === '23505') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Database error' });
    }
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    // "Auto-login" via long-lived cookie
    res.cookie('userId', user.id, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });
    res.json({ success: true, username: user.username });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('userId');
  res.json({ success: true });
});

// Check Session
app.get('/api/me', async (req, res) => {
  const userId = req.cookies.userId;
  if (!userId) return res.json({ user: null });
  
  try {
    const result = await pool.query('SELECT id, username FROM users WHERE id = $1', [userId]);
    res.json({ user: result.rows[0] || null });
  } catch (err) {
    res.json({ user: null });
  }
});

// --- Post CRUD API ---

// Get all posts
app.get('/api/posts', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.username, 
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as likes_count
      FROM posts p 
      JOIN users u ON p.user_id = u.id 
      ORDER BY p.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Get single post
app.get('/api/posts/:id', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.username,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as likes_count
      FROM posts p 
      JOIN users u ON p.user_id = u.id 
      WHERE p.id = $1
    `, [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Post not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Create post
app.post('/api/posts', authenticate, async (req, res) => {
  const { title, content } = req.body;
  const userId = req.cookies.userId;
  try {
    const result = await pool.query(
      'INSERT INTO posts (user_id, title, content) VALUES ($1, $2, $3) RETURNING id',
      [userId, title, content]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Update post
app.put('/api/posts/:id', authenticate, async (req, res) => {
  const { title, content } = req.body;
  const userId = req.cookies.userId;
  const postId = req.params.id;
  try {
    const result = await pool.query(
      'UPDATE posts SET title = $1, content = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND user_id = $4',
      [title, content, postId, userId]
    );
    if (result.rowCount === 0) return res.status(403).json({ error: 'Unauthorized or not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Delete post
app.delete('/api/posts/:id', authenticate, async (req, res) => {
  const userId = req.cookies.userId;
  const postId = req.params.id;
  try {
    const result = await pool.query('DELETE FROM posts WHERE id = $1 AND user_id = $2', [postId, userId]);
    if (result.rowCount === 0) return res.status(403).json({ error: 'Unauthorized or not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// --- Comments & Likes API ---

// Get comments for a post
app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, u.username 
      FROM comments c 
      JOIN users u ON c.user_id = u.id 
      WHERE c.post_id = $1 
      ORDER BY c.created_at ASC
    `, [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Create comment
app.post('/api/posts/:id/comments', authenticate, async (req, res) => {
  const { content } = req.body;
  const userId = req.cookies.userId;
  const postId = req.params.id;
  try {
    await pool.query(
      'INSERT INTO comments (post_id, user_id, content) VALUES ($1, $2, $3)',
      [postId, userId, content]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Add like (recommendation)
app.post('/api/posts/:id/like', authenticate, async (req, res) => {
  const userId = req.cookies.userId;
  const postId = req.params.id;
  try {
    // Check if already liked
    const check = await pool.query('SELECT * FROM likes WHERE post_id = $1 AND user_id = $2', [postId, userId]);
    if (check.rows.length > 0) {
      return res.status(400).json({ error: 'Already recommended' });
    }
    
    await pool.query('INSERT INTO likes (post_id, user_id) VALUES ($1, $2)', [postId, userId]);
    const countResult = await pool.query('SELECT COUNT(*) as count FROM likes WHERE post_id = $1', [postId]);
    res.json({ success: true, count: countResult.rows[0].count });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
