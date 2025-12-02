const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Database path
const DB_PATH = path.join(__dirname, 'database.json');

// Initialize database
if (!fs.existsSync(DB_PATH)) {
  fs.writeFileSync(DB_PATH, JSON.stringify({ 
    accounts: [], 
    sessions: [] 
  }, null, 2));
}

// Database functions
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (error) {
    return { accounts: [], sessions: [] };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// Middleware security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "https://generativelanguage.googleapis.com"]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration
app.use(cors({
  origin: function(origin, callback) {
    callback(null, true);
  },
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Terlalu banyak permintaan, coba lagi nanti.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', limiter);

// API Keys pooling untuk Gemini
const GEMINI_KEYS = [
  process.env.GEMINI_API_KEY_1,
  process.env.GEMINI_API_KEY_2,
  process.env.GEMINI_API_KEY_3,
  process.env.GEMINI_API_KEY_4,
  process.env.GEMINI_API_KEY_5
].filter(key => key && key.trim() !== '');

let currentKeyIndex = 0;

function getNextGeminiKey() {
  if (GEMINI_KEYS.length === 0) return null;
  const key = GEMINI_KEYS[currentKeyIndex];
  currentKeyIndex = (currentKeyIndex + 1) % GEMINI_KEYS.length;
  return key;
}

// System prompts
const SYSTEM_PROMPTS = {
  wormgpt: process.env.SYSTEM_PROMPT_WORM || `Anda adalah WormGPT, asisten AI teknis tingkat lanjut untuk penelitian keamanan Siber dan Penetrasi Keamanan...`,
  visora: process.env.SYSTEM_PROMPT_VISORA || `Anda adalah Visora AI, asisten AI yang responsif dan natural seperti chatGPT, Qwen, atau Claude...`
};

// ========== AUTHENTICATION ENDPOINTS ==========

// Create account endpoint
app.post('/api/create-account', (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.json({ success: false, message: 'Email dan password wajib diisi' });
    }
    
    const db = readDB();
    
    // Check if account exists
    const exists = db.accounts.find(acc => acc.email === email);
    if (exists) {
      return res.json({ success: false, message: 'Email sudah terdaftar' });
    }
    
    // Add new account
    db.accounts.push({
      email,
      password, // In production, hash this!
      createdAt: new Date().toISOString()
    });
    
    writeDB(db);
    
    res.json({ 
      success: true, 
      message: 'Akun berhasil dibuat',
      email: email
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Login endpoint
app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    
    const db = readDB();
    const account = db.accounts.find(acc => acc.email === email && acc.password === password);
    
    if (!account) {
      return res.json({ success: false, message: 'Email atau password salah' });
    }
    
    // Create session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    
    // Clean old sessions for this user
    db.sessions = db.sessions.filter(s => s.email !== email);
    
    // Add new session
    db.sessions.push({
      token: sessionToken,
      email: email,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() // 7 days
    });
    
    writeDB(db);
    
    res.json({ 
      success: true, 
      token: sessionToken,
      email: email 
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Verify session endpoint
app.post('/api/verify-session', (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.json({ valid: false });
    }
    
    const db = readDB();
    const session = db.sessions.find(s => s.token === token);
    
    if (!session) {
      return res.json({ valid: false });
    }
    
    // Check if expired
    if (new Date(session.expiresAt) < new Date()) {
      // Remove expired session
      db.sessions = db.sessions.filter(s => s.token !== token);
      writeDB(db);
      return res.json({ valid: false });
    }
    
    res.json({ 
      valid: true,
      email: session.email 
    });
  } catch (error) {
    res.json({ valid: false });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  try {
    const { token } = req.body;
    
    const db = readDB();
    db.sessions = db.sessions.filter(s => s.token !== token);
    writeDB(db);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Middleware to check authentication
function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '') || req.body.token;
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Token tidak ditemukan' });
  }
  
  const db = readDB();
  const session = db.sessions.find(s => s.token === token);
  
  if (!session || new Date(session.expiresAt) < new Date()) {
    return res.status(401).json({ error: 'Unauthorized', message: 'Session tidak valid atau expired' });
  }
  
  req.user = { email: session.email };
  next();
}

// ========== CHAT ENDPOINTS ==========

// Main chat endpoint (PROTECTED)
app.post('/api/chat', requireAuth, async (req, res) => {
  try {
    const { messages, model, imageBase64 } = req.body;
    
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'Format messages tidak valid' });
    }

    const apiKey = getNextGeminiKey();
    if (!apiKey) {
      return res.status(500).json({ error: 'API Key Gemini tidak tersedia' });
    }

    // Model selection
    const MODEL_NAME = model === 'visora' 
      ? 'gemini-1.5-flash' 
      : 'gemini-1.5-flash';

    const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent?key=${apiKey}`;

    const payload = {
      contents: messages,
      generationConfig: {
        maxOutputTokens: 4096,
        temperature: model === 'wormgpt' ? 0.9 : 0.7,
        topP: 0.95,
        topK: 40
      },
      safetySettings: [
        {
          category: "HARM_CATEGORY_HARASSMENT",
          threshold: "BLOCK_NONE"
        },
        {
          category: "HARM_CATEGORY_HATE_SPEECH",
          threshold: "BLOCK_NONE"
        },
        {
          category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
          threshold: "BLOCK_NONE"
        },
        {
          category: "HARM_CATEGORY_DANGEROUS_CONTENT",
          threshold: "BLOCK_NONE"
        }
      ]
    };

    // Add system instruction
    if (SYSTEM_PROMPTS[model]) {
      payload.systemInstruction = {
        parts: [{ text: SYSTEM_PROMPTS[model] }]
      };
    }

    // Add image if present
    if (imageBase64) {
      const lastMessage = messages[messages.length - 1];
      if (lastMessage && lastMessage.parts) {
        lastMessage.parts.push({
          inlineData: {
            mimeType: imageBase64.split(';')[0].split(':')[1],
            data: imageBase64.split(',')[1]
          }
        });
      }
    }

    // Call Gemini API
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();

    if (!response.ok) {
      console.error('Gemini API Error:', result);
      
      if (response.status === 429 || response.status === 403) {
        return res.status(429).json({ 
          error: 'Rate limited. Silakan coba lagi.',
          retry: true 
        });
      }
      
      throw new Error(result.error?.message || 'API Error');
    }

    const candidate = result.candidates?.[0];
    if (!candidate) {
      throw new Error('No candidate in response');
    }

    if (candidate.finishReason === 'SAFETY') {
      throw new Error('Response blocked by safety filters');
    }

    const aiContent = candidate.content?.parts?.[0]?.text;
    if (!aiContent) {
      throw new Error('Empty AI response');
    }

    res.json({
      success: true,
      content: aiContent,
      finishReason: candidate.finishReason,
      modelUsed: MODEL_NAME
    });

  } catch (error) {
    console.error('Server Error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  const db = readDB();
  res.json({ 
    status: 'healthy',
    service: 'WormGPT & Visora AI API',
    version: '2.1.0',
    availableKeys: GEMINI_KEYS.length,
    models: ['wormgpt', 'visora'],
    totalAccounts: db.accounts.length,
    activeSessions: db.sessions.filter(s => new Date(s.expiresAt) > new Date()).length,
    timestamp: new Date().toISOString()
  });
});

// Serve static files from public directory
app.use(express.static('public'));

// Fallback route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔑 Available Gemini Keys: ${GEMINI_KEYS.length}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 Auth system: ENABLED`);
});

module.exports = app;
