// ========================================
// GLOBETALK - FULL BACKEND (Final)
// Node.js + Express + Socket.io + MongoDB + Resend
// ========================================

const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// Allowed websites. Add your own domain later via the ALLOWED_ORIGINS env var (comma separated), no code change needed.
const EXTRA_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({
  origin: [/\.vercel\.app$/, /\.netlify\.app$/, 'http://localhost:3000', 'http://localhost:5500', ...EXTRA_ORIGINS],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));

// ========== DATABASE ==========
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/globetalk')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Error:', err.message));

// ========== EMAIL (RESEND HTTP API) ==========
const RESEND_API_KEY = process.env.RESEND_API_KEY;

async function sendEmailViaResend(to, subject, html) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY not set');
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'GlobeTalk <onboarding@resend.dev>',
      to: to,
      subject: subject,
      html: html
    })
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'Resend API error');
  console.log('✅ Email sent:', data.id);
  return data;
}

console.log('✅ Email service ready (Resend HTTP API)');

// ========== SCHEMAS ==========
const otpSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, trim: true },
  otp: { type: String, required: true },
  attempts: { type: Number, default: 0 },
  resendCount: { type: Number, default: 0 },
  lastResendTime: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 10 * 60 * 1000) },
  verified: { type: Boolean, default: false },
  lockedUntil: { type: Date, default: null },
  ip: { type: String, default: null }
});
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const OTP = mongoose.model('OTP', otpSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, sparse: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: String,
  name: String,
  country: String,
  age: Number,
  interests: [String],
  languages: [String],
  isVerified: { type: Boolean, default: false },
  isPremium: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  banReason: String,
  safetyStrikes: { type: Number, default: 0 },
  coins: { type: Number, default: 0 },
  welcomeBonus: { type: Boolean, default: false },
  rating: { type: Number, default: 5 },
  ratingCount: { type: Number, default: 0 },
  connectedWith: { type: Number, default: 0 },
  countriesMet: { type: Number, default: 0 },
  blockedUsers: [String],
  identityVerified: { type: Boolean, default: false },
  faceMatchScore: Number,
  livenessVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  senderId: String,
  receiverId: String,
  senderName: String,
  text: String,
  translatedText: String,
  fromLang: String,
  toLang: String,
  roomId: String,
  timestamp: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 }   // chat messages auto-delete after 30 days
});

const reportSchema = new mongoose.Schema({
  reporterId: String,
  reportedUserId: String,
  reason: String,
  details: String,
  timestamp: { type: Date, default: Date.now },
  status: { type: String, default: 'pending' }
});

const safetyLogSchema = new mongoose.Schema({
  userId: String,
  event: String,
  data: Object,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Report = mongoose.model('Report', reportSchema);
const SafetyLog = mongoose.model('SafetyLog', safetyLogSchema);

// ========== WALLET / GIFTS / MODERATION / TEST MODE ==========
const WELCOME_COINS = parseInt(process.env.WELCOME_COINS || '200', 10);   // virtual in-app coins, no cash value
const MOD_STRIKES_TO_BAN = parseInt(process.env.MOD_STRIKES_TO_BAN || '3', 10);
const TEST_EMAILS = (process.env.TEST_EMAILS || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
const GIFTS = [
  { id: 'diya',   emoji: '🪔', name: 'A diya for your Diwali',         price: 10 },
  { id: 'patake', emoji: '🎆', name: 'Patake (fireworks) for you',     price: 25 },
  { id: 'chai',   emoji: '🍵', name: 'Chai with me',                  price: 10 },
  { id: 'coffee', emoji: '☕', name: 'Have a coffee with me',          price: 15 },
  { id: 'rose',   emoji: '🌹', name: 'A rose for you',                 price: 20 },
  { id: 'date',   emoji: '💕', name: 'I want to go on a date with you', price: 50 },
  { id: 'ring',   emoji: '💍', name: 'I want to gift you a ring',      price: 100 }
];
const BAD_RE = [
  [/\b(f+u+c*k+|fck|motherf\w*|b+i+t+c+h+|a+s+s+h+o+l+e+|bastard|cunt|whore|slut|dickhead)\b/, 'abusive language'],
  [/\b(m+a+d+a+r+c+h+o+d+|bh?e+n+c+h+o+d+|c+h+u+t+i+y+a+|g+a+a*n+d+u+|r+a+n+d+i+|bh?o+s+d+i+k*)\b/, 'abusive language'],
  [/\b(nudes?|naked|porn\w*|sex|sexting|horny|boobs?|pussy|dick|cock|blowjob|handjob|chudai|lund|nangi|nanga)\b/, 'adult content']
];
const BAD_DEVANAGARI = ['मादरचोद', 'भेनचोद', 'बहनचोद', 'चूतिया', 'रंडी', 'चुदाई', 'लंड'];
function moderateText(text) {
  const raw = String(text || '').toLowerCase();
  for (const w of BAD_DEVANAGARI) if (raw.includes(w)) return 'abusive language';
  const t = raw.replace(/[@$]/g, 'a').replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
               .replace(/[^a-z\s]/g, ' ').replace(/\s+/g, ' ');
  for (const [re, label] of BAD_RE) if (re.test(t)) return label;
  return null;
}
async function handleViolation(socket, reason, weight = 1) {
  let strikes = null, banned = false;
  if (socket.email) {
    const u = await User.findOneAndUpdate({ email: socket.email }, { $inc: { safetyStrikes: weight } }, { new: true });
    if (u) {
      strikes = u.safetyStrikes;
      if (strikes >= MOD_STRIKES_TO_BAN && !u.isBanned) { u.isBanned = true; u.banReason = 'Chat violation: ' + reason; await u.save(); banned = true; }
    }
  }
  console.log(`🚫 Blocked (${reason}) from ${socket.email || socket.id} strikes=${strikes} banned=${banned}`);
  if (banned) {
    socket.emit('banned', { message: 'Your account is permanently banned for ' + reason + '.' });
    setTimeout(() => socket.disconnect(true), 500);
  } else {
    socket.emit('moderation-warning', { message: 'Blocked (' + reason + ').' + (strikes ? ` Warning ${strikes}/${MOD_STRIKES_TO_BAN} — repeated violations mean a permanent ban.` : '') });
  }
}

// ========== HELPERS ==========
const generateToken = (payload, expiresIn = '24h') => {
  return jwt.sign(payload, process.env.JWT_SECRET || 'fallback_secret', { expiresIn });
};

const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).toLowerCase());
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const buildEmailHTML = (otp) => `
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,sans-serif;">
  <div style="max-width:520px;margin:30px auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#2563eb 0%,#1d4ed8 100%);padding:30px 20px;text-align:center;">
      <div style="font-size:42px;margin-bottom:8px;">🌍</div>
      <h1 style="margin:0;color:#fff;font-size:26px;">GlobeTalk</h1>
      <p style="margin:6px 0 0;color:#FFD700;font-size:13px;">वसुधैव कुटुम्बकम्</p>
    </div>
    <div style="padding:36px 28px;text-align:center;">
      <h2 style="margin:0 0 12px;color:#1e293b;font-size:20px;">Verify Your Email</h2>
      <p style="margin:0 0 24px;color:#64748b;font-size:14px;">Use this code to complete your GlobeTalk signup. Expires in <strong style="color:#dc2626;">10 minutes</strong>.</p>
      <div style="background:#eff6ff;border:2px dashed #2563eb;border-radius:12px;padding:22px 16px;margin:0 0 24px;">
        <p style="margin:0 0 8px;color:#64748b;font-size:12px;">YOUR CODE</p>
        <div style="font-size:38px;font-weight:800;color:#2563eb;letter-spacing:12px;font-family:'Courier New',monospace;">${otp}</div>
      </div>
      <p style="margin:0;color:#94a3b8;font-size:12px;">If you didn't request this, ignore this email.</p>
    </div>
    <div style="background:#f8fafc;padding:20px;text-align:center;border-top:1px solid #e2e8f0;">
      <p style="margin:0;color:#64748b;font-size:12px;">Made with ❤️ in India 🇮🇳<br><strong>Thar Digital Ventures</strong></p>
    </div>
  </div>
</body></html>`;

// ========== REST API ==========
app.get('/api/health', (req, res) => {
  res.json({
    status: '✅ Server Running',
    timestamp: new Date(),
    features: ['email-otp', 'webrtc', 'matching', 'safety', 'identity-verification', 'gifts'],
    onlineUsers: Object.keys(activeUsers).length,
    waitingQueue: waitingQueue.length
  });
});

app.get('/', (req, res) => {
  res.json({ message: '🌍 GlobeTalk Server is LIVE', status: 'healthy' });
});

// ========== EMAIL OTP ==========
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }
    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser && existingUser.isBanned) {
      return res.status(403).json({ success: false, message: 'This account is banned.' });
    }

    const locked = await OTP.findOne({ email: normalizedEmail, lockedUntil: { $gt: new Date() } });
    if (locked) {
      return res.status(423).json({ success: false, message: 'Too many attempts. Try later.' });
    }

    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recent = await OTP.countDocuments({ email: normalizedEmail, createdAt: { $gte: oneHourAgo } });
    if (recent >= 5) {
      return res.status(429).json({ success: false, message: 'Too many OTP requests. Wait 1 hour.' });
    }

    await OTP.deleteMany({ email: normalizedEmail, verified: false });

    const otp = generateOTP();
    await OTP.create({
      email: normalizedEmail,
      otp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    if (TEST_EMAILS.includes(normalizedEmail)) {
      console.log(`🧪 TEST OTP for ${normalizedEmail}: ${otp}`);   // test mode: read it in Render Logs
    } else {
      await sendEmailViaResend(
        normalizedEmail,
        `Your GlobeTalk Verification Code: ${otp}`,
        buildEmailHTML(otp)
      );
    }

    console.log(`📧 OTP sent to ${normalizedEmail}`);
    res.json({ success: true, message: 'OTP sent successfully.', expiresIn: 600 });
  } catch (err) {
    console.error('❌ Send OTP error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to send OTP.' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ success: false, message: 'Email and OTP required' });

    const normalizedEmail = email.toLowerCase().trim();
    const record = await OTP.findOne({ email: normalizedEmail, verified: false }).sort({ createdAt: -1 });

    if (!record) return res.status(410).json({ success: false, message: 'OTP expired. Request new.' });
    if (record.expiresAt < new Date()) return res.status(410).json({ success: false, message: 'OTP expired.' });

    if (record.otp !== otp.trim()) {
      record.attempts += 1;
      if (record.attempts >= 5) {
        record.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
      }
      await record.save();
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    record.verified = true;
    await record.save();

    // Create or update user
    let user = await User.findOne({ email: normalizedEmail });
    if (user && user.isBanned) return res.status(403).json({ success: false, message: 'This account is banned.' });
    if (!user) {
      user = await User.create({
        email: normalizedEmail,
        name: normalizedEmail.split('@')[0],
        username: normalizedEmail.split('@')[0] + '_' + Date.now().toString(36)
      });
    }

    const token = generateToken({ email: normalizedEmail, verified: true, userId: user._id }, '24h');

    console.log(`✅ OTP verified: ${normalizedEmail}`);
    res.json({
      success: true,
      message: 'Verified successfully',
      token,
      user: { id: user._id, email: user.email, name: user.name, verified: true }
    });
  } catch (err) {
    console.error('❌ Verify OTP error:', err.message);
    res.status(500).json({ success: false, message: 'Verification failed.' });
  }
});

app.post('/api/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !validateEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email' });

    const normalizedEmail = email.toLowerCase().trim();
    const existing = await OTP.findOne({ email: normalizedEmail, verified: false }).sort({ createdAt: -1 });
    if (!existing) return res.status(410).json({ success: false, message: 'No active OTP.' });

    const newOTP = generateOTP();
    existing.otp = newOTP;
    existing.resendCount += 1;
    existing.lastResendTime = new Date();
    existing.expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    existing.attempts = 0;
    await existing.save();

    await sendEmailViaResend(
      normalizedEmail,
      `Your New GlobeTalk Code: ${newOTP}`,
      buildEmailHTML(newOTP)
    );

    res.json({ success: true, message: 'OTP resent.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to resend.' });
  }
});

// ========== IDENTITY VERIFICATION ==========
app.post('/api/verify-identity', async (req, res) => {
  try {
    const { email, dob, faceMatchScore, livenessVerified, ocrConfidence } = req.body;

    if (!email) return res.status(400).json({ success: false, message: 'Email required' });

    // Age check
    if (dob) {
      const age = Math.floor((Date.now() - new Date(dob).getTime()) / (365.25 * 24 * 3600 * 1000));
      if (age < 18) {
        return res.status(403).json({ success: false, message: 'Must be 18+' });
      }
    }

    // Face match check
    if (faceMatchScore && faceMatchScore < 0.6) {
      return res.status(400).json({ success: false, message: 'Face match failed. Try again.' });
    }

    // Update user
    await User.findOneAndUpdate(
      { email: email.toLowerCase() },
      {
        isVerified: true,
        identityVerified: true,
        faceMatchScore: faceMatchScore || 0,
        livenessVerified: livenessVerified || false
      },
      { upsert: true }
    );

    await SafetyLog.create({
      userId: email,
      event: 'IDENTITY_VERIFIED',
      data: { faceMatchScore, livenessVerified, ocrConfidence }
    });

    console.log(`✅ Identity verified: ${email}`);
    res.json({ success: true, message: 'Identity verified successfully' });
  } catch (err) {
    console.error('❌ Identity verify error:', err.message);
    res.status(500).json({ success: false, message: 'Verification failed.' });
  }
});

// ========== AUTH ==========
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, name, country } = req.body;
    let user = await User.findOne({ email: email?.toLowerCase() });
    if (user) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;
    user = await User.create({
      username: username || email.split('@')[0],
      email: email.toLowerCase(),
      password: hashedPassword,
      name, country
    });

    const token = generateToken({ id: user._id, email: user.email }, '7d');
    res.json({ success: true, message: 'Signup successful', token, user: { id: user._id, email, name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email?.toLowerCase() });
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (user.isBanned) return res.status(403).json({ error: 'Account banned' });

    if (password && user.password) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ error: 'Invalid password' });
    }

    const token = generateToken({ id: user._id, email: user.email }, '7d');
    res.json({ success: true, message: 'Login successful', token, user: { id: user._id, email, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== USER ==========
app.get('/api/user/profile/:email', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email.toLowerCase() }).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/user/stats/:email', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      success: true,
      stats: {
        connectedWith: user.connectedWith || 0,
        countriesMet: user.countriesMet || 0,
        rating: user.rating || 5,
        isVerified: user.isVerified || false,
        identityVerified: user.identityVerified || false
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/user/block', async (req, res) => {
  try {
    const { email, blockedEmail } = req.body;
    await User.findOneAndUpdate(
      { email: email?.toLowerCase() },
      { $addToSet: { blockedUsers: blockedEmail } }
    );
    res.json({ success: true, message: 'User blocked' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== REPORT ==========
app.post('/api/report', async (req, res) => {
  try {
    const { reporterId, reportedUserId, reason, details } = req.body;
    await Report.create({ reporterId, reportedUserId, reason, details });

    const critical = ['Underage User', 'Inappropriate Content', 'Harassment'];
    if (critical.includes(reason)) {
      await User.findByIdAndUpdate(reportedUserId, { $inc: { safetyStrikes: 1 } });
      const user = await User.findById(reportedUserId);
      if (user && user.safetyStrikes >= 3) {
        user.isBanned = true;
        user.banReason = 'Multiple critical reports';
        await user.save();
      }
    }
    res.json({ success: true, message: 'Report submitted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== SAFETY LOG ==========
app.post('/api/safety-log', async (req, res) => {
  try {
    await SafetyLog.create(req.body);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== SOCKET.IO ==========
const activeUsers = {};
const waitingQueue = [];
const rooms = {};

function findMatch(socket) {
  const currentUser = activeUsers[socket.id];
  if (!currentUser) return;

  for (let i = waitingQueue.length - 1; i >= 0; i--) {
    if (!activeUsers[waitingQueue[i]]) waitingQueue.splice(i, 1);
  }

  const partnerId = waitingQueue.shift();
  if (partnerId && activeUsers[partnerId] && partnerId !== socket.id) {
    const partner = activeUsers[partnerId];
    const roomId = [socket.id, partnerId].sort().join('-');

    rooms[roomId] = { user1: socket.id, user2: partnerId };
    socket.join(roomId);
    io.sockets.sockets.get(partnerId)?.join(roomId);

    const matchPercent = 85 + Math.floor(Math.random() * 15);

    io.to(socket.id).emit('stranger-found', {
      remoteUserId: partnerId,
      match: matchPercent,
      profile: { name: partner.username, country: partner.country, verified: partner.isVerified }
    });

    io.to(partnerId).emit('stranger-found', {
      remoteUserId: socket.id,
      match: matchPercent,
      profile: { name: currentUser.username, country: currentUser.country, verified: currentUser.isVerified }
    });

    console.log(`🎯 Matched: ${currentUser.username} ↔ ${partner.username}`);
  } else {
    if (!waitingQueue.includes(socket.id)) waitingQueue.push(socket.id);
    socket.emit('waiting', { message: 'Waiting for stranger...' });
  }
}

// Broadcast online users list
function broadcastOnlineUsers() {
  const users = Object.values(activeUsers).map(u => ({
    id: u.userId,
    name: u.username,
    country: u.country,
    isVerified: u.isVerified
  }));
  io.emit('users:online', users);
  io.emit('online:count', users.length);
}

io.on('connection', (socket) => {
  console.log(`✅ Connected: ${socket.id}`);

  socket.on('user-join', (data) => {
    activeUsers[socket.id] = {
      socketId: socket.id,
      userId: data.userId || data.email || socket.id,
      username: data.username || data.name || 'User_' + socket.id.substr(0, 4),
      country: data.country || 'India',
      isVerified: data.isVerified || false
    };
    broadcastOnlineUsers();
    try { socket.email = jwt.verify(data.token, process.env.JWT_SECRET || 'fallback_secret').email; } catch (e) { socket.email = null; }
    socket.emit('gift:catalog', { gifts: GIFTS });
    if (socket.email) (async () => {
      try {
        let u = await User.findOneAndUpdate({ email: socket.email, welcomeBonus: { $ne: true } },
          { $set: { welcomeBonus: true }, $inc: { coins: WELCOME_COINS } }, { new: true });
        const welcome = !!u;
        if (!u) u = await User.findOne({ email: socket.email });
        if (u) socket.emit('wallet:update', { coins: u.coins || 0, welcome });
      } catch (e) { console.error('Wallet error:', e.message); }
    })();
  });

  socket.on('match_request', () => findMatch(socket));
  socket.on('find-stranger', () => findMatch(socket));

  socket.on('webrtc-offer', (data) => {
    if (data.to && io.sockets.sockets.get(data.to)) {
      io.to(data.to).emit('webrtc-offer', { from: socket.id, offer: data.offer });
    }
  });

  socket.on('webrtc-answer', (data) => {
    if (data.to && io.sockets.sockets.get(data.to)) {
      io.to(data.to).emit('webrtc-answer', { from: socket.id, answer: data.answer });
    }
  });

  socket.on('ice-candidate', (data) => {
    if (data.to && io.sockets.sockets.get(data.to)) {
      io.to(data.to).emit('ice-candidate', { from: socket.id, candidate: data.candidate });
    }
  });

  socket.on('message', async (data) => {
    try {
      const flagged = moderateText(data.text);
      if (flagged) { await handleViolation(socket, flagged); return; }
      await Message.create({
        senderId: data.from,
        receiverId: data.to,
        senderName: data.senderName,
        text: data.text,
        fromLang: data.language,
        toLang: data.targetLang,
        roomId: data.roomId
      });

      // Broadcast to room
      if (data.roomId) {
        socket.to(data.roomId).emit('message', {
          from: data.senderName || 'Stranger',
          text: data.text,
          language: data.language
        });
      }
    } catch (err) {
      console.error('Message error:', err.message);
    }
  });

  // ========== GIFTS ==========
  socket.on('gift:send', async (data) => {
    try {
      const g = GIFTS.find(x => x.id === data.giftId);
      if (!g) return socket.emit('gift:error', { message: 'Unknown gift' });
      if (!socket.email) return socket.emit('gift:error', { message: 'Please log in again' });
      if (!data.roomId || !socket.rooms.has(data.roomId)) return socket.emit('gift:error', { message: 'No stranger connected' });
      const u = await User.findOneAndUpdate({ email: socket.email, coins: { $gte: g.price } }, { $inc: { coins: -g.price } }, { new: true });
      if (!u) return socket.emit('gift:error', { message: 'Not enough coins for ' + g.name });
      socket.emit('wallet:update', { coins: u.coins });
      socket.emit('gift:sent', { emoji: g.emoji, name: g.name });
      socket.to(data.roomId).emit('gift:received', { emoji: g.emoji, name: g.name, from: data.from || 'Stranger' });
      console.log(`🎁 ${socket.email} sent ${g.id}`);
    } catch (err) { console.error('Gift error:', err.message); }
  });

  // Receiver's browser detected explicit video from the stranger (nudity model runs on the receiver's device)
  socket.on('nsfw-detected', async (data) => {
    try {
      const now = Date.now();
      if (socket.lastNsfw && now - socket.lastNsfw < 5000) return;          // rate limit per reporter
      socket.lastNsfw = now;
      const target = io.sockets.sockets.get(data.partner);
      if (!target || !data.roomId || !socket.rooms.has(data.roomId) || !target.rooms.has(data.roomId)) return;
      await Report.create({ reporterId: socket.email || socket.id, reportedUserId: target.email || target.id,
        reason: 'AI: explicit video', details: 'auto-detected in receiver browser' });
      await handleViolation(target, 'explicit video content', 2);            // video counts as 2 strikes
    } catch (e) { console.error('nsfw report error:', e.message); }
  });

  socket.on('report-user', async (data) => {
    try {
      await Report.create({
        reporterId: socket.id,
        reportedUserId: data.reportedUser,
        reason: data.reason,
        details: data.details || ''
      });
      console.log(`📢 Report: ${data.reason}`);
    } catch (err) {}
  });

  socket.on('safety-log', async (data) => {
    try { await SafetyLog.create(data); } catch (err) {}
  });

  socket.on('user-left', () => {
    const idx = waitingQueue.indexOf(socket.id);
    if (idx > -1) waitingQueue.splice(idx, 1);

    for (const roomId in rooms) {
      const room = rooms[roomId];
      if (room.user1 === socket.id || room.user2 === socket.id) {
        const partnerId = room.user1 === socket.id ? room.user2 : room.user1;
        io.to(partnerId).emit('user-left', { message: 'Stranger left' });
        delete rooms[roomId];
      }
    }
  });

  socket.on('disconnect', () => {
    const idx = waitingQueue.indexOf(socket.id);
    if (idx > -1) waitingQueue.splice(idx, 1);

    for (const roomId in rooms) {
      const room = rooms[roomId];
      if (room.user1 === socket.id || room.user2 === socket.id) {
        const partnerId = room.user1 === socket.id ? room.user2 : room.user1;
        io.to(partnerId).emit('user-left', { message: 'Stranger disconnected' });
        delete rooms[roomId];
      }
    }
    delete activeUsers[socket.id];
    broadcastOnlineUsers();
  });
});

// ========== START ==========
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════╗
  ║   🌍 GLOBETALK SERVER RUNNING     ║
  ║   Made in India 🇮🇳                ║
  ╠════════════════════════════════════╣
  ║   📍 Port: ${PORT}
  ║   📧 Email: Resend HTTP API
  ║   🎥 WebRTC: Ready
  ║   🎁 Gifts: Ready
  ║   🆔 Identity: Ready
  ╚════════════════════════════════════╝
  `);
});

process.on('uncaughtException', (err) => console.error('💥', err.message));
process.on('unhandledRejection', (reason) => console.error('💥', reason));

module.exports = server;
