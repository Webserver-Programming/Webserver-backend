const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 5000;
const secretKey = 'your_secret_key'; // JWT 비밀키

// Middleware
app.use(cors());
app.use(bodyParser.json());

console.log('Initializing server...');

// MySQL Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234',
  database: 'web_server' //이부분은 각자 만든 데이터베이스 이름
});

console.log('Connecting to MySQL...');

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('MySQL Connected...');
});

console.log('Setting up middleware and routes...');

// Middleware to verify JWT token
const authenticateJWT = (req, res, next) => {
  console.log('Authenticating JWT...');
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        console.log('JWT verification failed:', err);
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    console.log('No token provided');
    res.sendStatus(401);
  }
};

// Register Endpoint
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('Received registration data:', { username, email, password });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(query, [username, email, hashedPassword], (err, result) => {
      if (err) {
        console.error('Database error:', err);
        res.status(500).send({ error: 'Database error' });
      } else {
        console.log('User registered successfully:', result);
        res.status(201).send({ message: 'User registered successfully' });
      }
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    res.status(500).send({ error: 'Error hashing password' });
  }
});

// Login Endpoint
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  console.log('Received login data:', { email, password });

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).send({ error: 'Database error' });
    } else if (results.length > 0) {
      const user = results[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });
        console.log('Login successful:', user);
        res.status(200).send({ message: 'Login successful', token });
      } else {
        console.log('Invalid credentials');
        res.status(401).send({ error: 'Invalid credentials' });
      }
    } else {
      console.log('Invalid credentials');
      res.status(401).send({ error: 'Invalid credentials' });
    }
  });
});

// Post Endpoint
app.post('/api/posts', authenticateJWT, (req, res) => {
  console.log('Received a post request');
  const { title, content } = req.body;
  const author_id = req.user.userId;

  console.log('Received post data:', { title, content, author_id });

  const query = 'INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)';
  db.query(query, [title, content, author_id], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: err.message });
    }
    console.log('Post created successfully:', result);
    res.status(201).json({ message: 'Post created successfully', postId: result.insertId });
  });
});

// Get all posts for a user
app.get('/api/posts', authenticateJWT, (req, res) => {
  const userId = req.user.userId;
  const query = 'SELECT * FROM posts WHERE author_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).send({ error: 'Database error' });
    } else {
      res.status(200).send(results);
    }
  });
});

// Get a specific post by id
app.get('/api/posts/:id', authenticateJWT, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.userId;
  const query = 'SELECT * FROM posts WHERE id = ? AND author_id = ?';
  db.query(query, [postId, userId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).send({ error: 'Database error' });
    } else if (results.length > 0) {
      res.status(200).send(results[0]);
    } else {
      res.status(404).send({ error: 'Post not found or not authorized' });
    }
  });
});

// Update a post
app.put('/api/posts/:id', authenticateJWT, (req, res) => {
  const postId = req.params.id;
  const { title, content } = req.body;
  const userId = req.user.userId;
  const query = 'UPDATE posts SET title = ?, content = ? WHERE id = ? AND author_id = ?';

  db.query(query, [title, content, postId, userId], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Post not found or not authorized' });
    }
    res.status(200).json({ message: 'Post updated successfully' });
  });
});

// Delete a post
app.delete('/api/posts/:id', authenticateJWT, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.userId;
  const query = 'DELETE FROM posts WHERE id = ? AND author_id = ?';

  db.query(query, [postId, userId], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Post not found or not authorized' });
    }
    res.status(200).json({ message: 'Post deleted successfully' });
  });
});

// Like a post
app.post('/api/posts/:id/like', authenticateJWT, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.userId;

  const checkLikeQuery = 'SELECT * FROM likes WHERE user_id = ? AND post_id = ?';
  db.query(checkLikeQuery, [userId, postId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length > 0) {
      // User already liked this post, so we remove the like (unlike)
      const deleteLikeQuery = 'DELETE FROM likes WHERE user_id = ? AND post_id = ?';
      db.query(deleteLikeQuery, [userId, postId], (err, result) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        return res.status(200).json({ message: 'Like removed successfully' });
      });
    } else {
      // User has not liked this post yet, so we add the like
      const insertLikeQuery = 'INSERT INTO likes (user_id, post_id) VALUES (?, ?)';
      db.query(insertLikeQuery, [userId, postId], (err, result) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        return res.status(201).json({ message: 'Like added successfully' });
      });
    }
  });
});

// Get likes count for a post
app.get('/api/posts/:id/likes', authenticateJWT, (req, res) => {
  const postId = req.params.id;
  const query = 'SELECT COUNT(*) as likes FROM likes WHERE post_id = ?';
  db.query(query, [postId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(200).json(results[0]);
  });
});

// Check if user liked the post
app.get('/api/posts/:id/like-status', authenticateJWT, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.userId;

  const query = 'SELECT * FROM likes WHERE post_id = ? AND user_id = ?';
  db.query(query, [postId, userId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      res.status(500).send({ error: 'Database error' });
    } else {
      const liked = results.length > 0;
      res.status(200).send({ liked });
    }
  });
});

// Example of an authenticated route
app.get('/api/protected', authenticateJWT, (req, res) => {
  console.log('Accessing protected route');
  res.send('This is a protected route');
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
