require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json()); // Parse JSON bodies
app.use(cors());         // Allow requests from your Flutter app

// ==========================================
// 1. DATABASE CONNECTION
// ==========================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ==========================================
// 2. SCHEMAS & MODELS
// ==========================================
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passcode: { type: String, required: true }, 
}, { timestamps: true });

const taskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: { type: String, default: '' },
  date: { type: Date, required: true },
  isCompleted: { type: Boolean, default: false }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Task = mongoose.model('Task', taskSchema);

// ==========================================
// 3. AUTH MIDDLEWARE
// ==========================================
// Protects routes by verifying the JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer <token>"

  if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
    if (err) return res.status(403).json({ message: 'Invalid or Expired Token' });
    req.user = decodedUser; // Attach the decoded payload ({ userId: ... }) to the request
    next();
  });
}

// ==========================================
// 4. AUTHENTICATION ROUTES
// ==========================================

// REGISTER: Create a new user with a hashed passcode
app.post('/api/register', async (req, res) => {
  try {
    const { username, passcode } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: 'Username already taken' });

    // Hash the passcode (salt rounds = 10)
    const hashedPasscode = await bcrypt.hash(passcode, 10);

    const newUser = new User({ username, passcode: hashedPasscode });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error during registration', error: error.message });
  }
});

// LOGIN: Verify passcode and return JWT
app.post('/api/login', async (req, res) => {
  try {
    const { username, passcode } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Compare raw passcode with the hashed one in the DB
    const isMatch = await bcrypt.compare(passcode, user.passcode);
    if (!isMatch) return res.status(401).json({ message: 'Invalid passcode' });

    // Generate JWT lasting for 7 days
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ token, userId: user._id, username: user.username });
  } catch (error) {
    res.status(500).json({ message: 'Server error during login', error: error.message });
  }
});

// READ (ALL USERS): Get a list of all registered users
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    // .select('-passcode') ensures we don't leak password hashes
    const users = await User.find().select('-passcode');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error: error.message });
  }
});

// DELETE USER: Remove a user and their associated tasks
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const userIdToDelete = req.params.id;

    // 1. Delete the user
    const deletedUser = await User.findByIdAndDelete(userIdToDelete);
    
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // 2. Cascade delete: Remove all tasks belonging to this user
    await Task.deleteMany({ userId: userIdToDelete });

    res.json({ 
      message: 'User and all associated tasks deleted successfully', 
      userId: userIdToDelete 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting user', error: error.message });
  }
});

// ==========================================
// 5. TASK CRUD ROUTES (Protected)
// ==========================================

// CREATE: Add a new task
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { title, description, date, isCompleted } = req.body;
    
    const newTask = new Task({
      userId: req.user.userId, // Pulled securely from the JWT
      title,
      description,
      date,
      isCompleted
    });

    const savedTask = await newTask.save();
    res.status(201).json(savedTask);
  } catch (error) {
    res.status(500).json({ message: 'Error creating task', error: error.message });
  }
});

// READ (ALL): Get all tasks for the logged-in user
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    // Only fetch tasks belonging to the authenticated user
    const tasks = await Task.find({ userId: req.user.userId }).sort({ date: 1 });
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching tasks', error: error.message });
  }
});

// READ (SINGLE): Get a specific task by ID
app.get('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!task) return res.status(404).json({ message: 'Task not found' });
    
    res.json(task);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching task', error: error.message });
  }
});

// UPDATE: Modify an existing task
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const { title, description, date, isCompleted } = req.body;
    
    // findOneAndUpdate ensures users can only update their OWN tasks
    const updatedTask = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { title, description, date, isCompleted },
      { new: true, runValidators: true } // Returns the updated document
    );

    if (!updatedTask) return res.status(404).json({ message: 'Task not found or unauthorized' });

    res.json(updatedTask);
  } catch (error) {
    res.status(500).json({ message: 'Error updating task', error: error.message });
  }
});

// DELETE: Remove a task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const deletedTask = await Task.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
    
    if (!deletedTask) return res.status(404).json({ message: 'Task not found or unauthorized' });

    res.json({ message: 'Task deleted successfully', taskId: deletedTask._id });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting task', error: error.message });
  }
});

// ==========================================
// 6. START SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});