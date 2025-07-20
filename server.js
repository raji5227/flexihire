const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// PostgreSQL Connection
const db = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

async function initializeDatabase() {
  try {
    await db.connect();
    console.log("✅ PostgreSQL connected successfully!");

    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Removed login_records table creation as per user request
    // await db.query(`
    //   CREATE TABLE IF NOT EXISTS login_records (
    //     id SERIAL PRIMARY KEY,
    //     user_id INTEGER REFERENCES users(id),
    //     login_time TIMESTAMP DEFAULT NOW(),
    //     ip_address TEXT,
    //     user_agent TEXT
    //   )
    // `);
    
    console.log("✅ Database tables initialized!");
  } catch (err) {
    console.error("❌ Database initialization error:", err);
  }
}

initializeDatabase();

// In-memory storage for OTP (for development)
const otpStorage = new Map(); // Format: { email: { otp: '123456', expires: Date } }

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ✅ Register Route (Generates OTP in console)
app.post('/register', async (req, res) => {
  const { fullName, email, password } = req.body;
  
  // Generate OTP
  const otp = generateOTP();
  const expires = new Date(Date.now() + 10 * 60000); // 10 minutes expiry
  
  // Store OTP in memory (instead of email)
  otpStorage.set(email, { otp, expires, userData: { fullName, email, password } });
  
  // Log OTP to console (for development)
  console.log(`📩 OTP for ${email}: ${otp} (Expires: ${expires.toLocaleTimeString()})`);
  
  res.status(200).json({ 
    message: 'OTP generated. Check your VS Code console for the OTP.',
    email,
    otp // Only for development! Remove in production
  });
});

// ✅ Verify OTP and Store Data
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  
  try {
    // Check if OTP exists and is valid
    const storedData = otpStorage.get(email);
    
    if (!storedData || storedData.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }
    
    if (new Date() > storedData.expires) {
      otpStorage.delete(email);
      return res.status(400).json({ error: 'OTP expired' });
    }
    
    // Store user in database after successful verification
    const { fullName, email, password } = storedData.userData;
    
    await db.query(
      'INSERT INTO users (full_name, email, password, is_verified) VALUES ($1, $2, $3, $4)',
      [fullName, email, password, true]
    );
    
    // Clear OTP from memory
    otpStorage.delete(email);
    
    res.status(200).json({ 
      message: 'OTP verified and user registered successfully',
      user: { fullName, email }
    });
    
  } catch (error) {
    if (error.code === '23505') { // Unique violation (email exists)
      return res.status(400).json({ error: 'Email already registered' });
    }
    console.error("❌ Verification error:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve frontend
app.use(express.static(path.join(__dirname, 'public')));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists and password matches
    const userResult = await db.query(
      'SELECT id, password FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = userResult.rows[0];

    // For simplicity, compare plain text passwords (in production, use hashed passwords)
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // No login record insertion as per user request

    res.status(200).json({ message: 'Login successful' });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
