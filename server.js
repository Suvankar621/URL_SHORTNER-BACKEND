const express = require('express');
require('dotenv').config();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');


const app = express();
const PORT = 5000;

app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET=process.env.JWT_SECRET;
// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI,{
    useNewUrlParser: true,
    useUnifiedTopology: true,
  
}).then(()=>{
    console.log("DB Connected")
});

// User Model
const User = mongoose.model('User', {
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

// URL Model
const Url = mongoose.model('Url', {
  originalUrl: { type: String, required: true },
  shortUrl: { type: String, unique: true, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

// Authentication Middleware
const authenticateUser = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'Authorization denied' });
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded.user;
      next();
    } catch (err) {
      res.status(401).json({ msg: 'Token is not valid' });
    }
  };
  

// Register User
app.post('/api/user/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ msg: 'Please enter all fields' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    // Create JWT token
    const token = jwt.sign({ user: { id: newUser.id } }, JWT_SECRET, { expiresIn: 3600 });
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Login User
app.post('/api/user/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Validate input
    if (!username || !password) {
      return res.status(400).json({ msg: 'Please enter all fields' });
    }

    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ msg: 'User does not exist' });
    }

    // Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign({ user: { id: user.id } }, JWT_SECRET, { expiresIn: 3600 });
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Shorten URL
app.post('/api/url/shorten', authenticateUser, async (req, res) => {
  const { originalUrl } = req.body;

  try {
    // Validate URL
    if (!validator.isURL(originalUrl)) {
      return res.status(400).json({ msg: 'Invalid URL' });
    }

    // Generate unique short URL
    const shortUrl = Math.random().toString(36).substring(7);

    // Create URL entry
    const newUrl = new Url({ originalUrl, shortUrl, userId: req.user.id });
    await newUrl.save();

    res.json({ shortUrl });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Example backend route
app.get('/api/url', authenticateUser, async (req, res) => {
    try {
      const urls = await Url.find({ userId: req.user.id });
      res.json(urls);
    } catch (error) {
      console.error(error.message);
      res.status(500).send('Server error');
    }
  });

  // Example backend route for deleting a URL
app.delete('/api/url/:id', authenticateUser, async (req, res) => {
    try {
      // Retrieve the URL ID from the request parameters
      const urlId = req.params.id;
  
      // Check if the URL belongs to the authenticated user (optional)
      const url = await Url.findById(urlId);
      if (!url || url.userId.toString() !== req.user.id) {
        return res.status(404).json({ msg: 'URL not found' });
      }
  
      // Delete the URL
      await Url.findByIdAndDelete(urlId);
  
      res.json({ msg: 'URL deleted successfully' });
    } catch (error) {
      console.error(error.message);
      res.status(500).send('Server error');
    }
  });

// Redirect to original URL
app.get('/:shortUrl', async (req, res) => {
  try {
    const url = await Url.findOne({ shortUrl: req.params.shortUrl });
    if (!url) {
      return res.status(404).json({ msg: 'URL not found' });
    }

    res.redirect(url.originalUrl);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Start server
app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));





