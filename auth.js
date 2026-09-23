// Login for the app: Google Sign-In + email OTP.
// Both methods end in the same place: a signed session token whose "uid" is a hash of the
// person's (normalized) email. Google login and OTP with the same email = the same account,
// so a permanent ban follows the email, not the browser.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');

const APP_NAME = process.env.APP_NAME || 'GlobeTalk';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) console.warn('[auth] JWT_SECRET is not set. Everyone will be logged out on each restart. Set it in .env');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID || '';
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET || '';
const facebookReady = !!(FACEBOOK_APP_ID && FACEBOOK_APP_SECRET);

const SESSION_DAYS = 30;
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

const smtpReady = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const smtpPort = Number(process.env.SMTP_PORT || 587);
const transporter = smtpReady
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;
if (!smtpReady) console.warn('[auth] SMTP not configured. OTP codes will be printed in this console (development mode only).');

// Add more domains here as you notice them. Throwaway inboxes make ban evasion easy.
const DISPOSABLE = new Set([
  'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org',
  'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com', 'dispostable.com', 'maildrop.cc',
]);

// ---------- helpers ----------
function normalizeEmail(raw) {
  const e = String(raw || '').trim().toLowerCase();
  if (e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return null;
  let [local, domain] = e.split('@');
  if (domain === 'googlemail.com') domain = 'gmail.com';
  if (domain === 'gmail.com') local = local.split('+')[0].replace(/\./g, ''); // a.b+x@gmail = ab@gmail
  return local + '@' + domain;
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const uidFor = (normEmail) => 'u_' + sha(normEmail).slice(0, 32);

function maskEmail(email) {
  const [l, d] = String(email).split('@');
  return (l.length <= 2 ? l[0] : l.slice(0, 2)) + '***@' + d;
}

function issueSession(email) {
  const norm = normalizeEmail(email);
  const uid = uidFor(norm);
  const token = jwt.sign({ uid }, JWT_SECRET, { expiresIn: SESSION_DAYS + 'd' });
  return { token, label: maskEmail(email) };
}

function verifySession(token) {
  try {
    const p = jwt.verify(String(token || ''), JWT_SECRET);
    return p && p.uid ? p.uid : null;
  } catch (e) {
    return null;
  }
}

// tiny in-memory rate limiter
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) { hits.set(key, arr); return true; }
  arr.push(now);
  hits.set(key, arr);
  return false;
}
setInterval(() => { for (const [k, v] of hits) if (!v.length) hits.delete(k); }, 10 * 60 * 1000).unref();

const ipOf = (req) => (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();

// ---------- routes ----------
const router = express.Router();

router.get('/config', (req, res) => {
  res.json({ googleClientId: GOOGLE_CLIENT_ID || null, facebookAppId: facebookReady ? FACEBOOK_APP_ID : null, appName: APP_NAME });
});

router.post('/google', async (req, res) => {
  if (!googleClient) return res.status(503).json({ error: 'Google login is not set up yet.' });
  if (limited('g:' + ipOf(req), 20, 10 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: String(req.body.credential || ''), audience: GOOGLE_CLIENT_ID });
    const p = ticket.getPayload();
    if (!p || !p.email || !p.email_verified) return res.status(400).json({ error: 'Your Google email is not verified.' });
    if (!normalizeEmail(p.email)) return res.status(400).json({ error: 'Invalid email.' });
    res.json(issueSession(p.email));
  } catch (e) {
    res.status(401).json({ error: 'Google sign-in failed. Please try again.' });
  }
});

router.post('/facebook', async (req, res) => {
  if (!facebookReady) return res.status(503).json({ error: 'Facebook login is not set up yet.' });
  if (limited('f:' + ipOf(req), 20, 10 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  const userToken = String(req.body.accessToken || '');
  if (!userToken) return res.status(400).json({ error: 'Missing Facebook token.' });
  try {
    // Verify the token was issued to OUR app (prevents someone sending a token from a different app)
    const appToken = FACEBOOK_APP_ID + '|' + FACEBOOK_APP_SECRET;
    const dbg = await (await fetch(`https://graph.facebook.com/debug_token?input_token=${encodeURIComponent(userToken)}&access_token=${encodeURIComponent(appToken)}`)).json();
    const info = dbg && dbg.data;
    if (!info || !info.is_valid || String(info.app_id) !== String(FACEBOOK_APP_ID)) {
      return res.status(401).json({ error: 'Facebook sign-in failed. Please try again.' });
    }
    // Fetch the verified email (requires the user to grant the "email" permission)
    const me = await (await fetch(`https://graph.facebook.com/me?fields=id,email&access_token=${encodeURIComponent(userToken)}`)).json();
    if (!me || !me.email || !normalizeEmail(me.email)) {
      return res.status(400).json({ error: 'Please allow email access to sign in with Facebook.' });
    }
    res.json(issueSession(me.email));
  } catch (e) {
    res.status(401).json({ error: 'Facebook sign-in failed. Please try again.' });
  }
});

const otpStore = new Map(); // normalizedEmail -> { hash, exp, attempts }

router.post('/otp/request', async (req, res) => {
  const norm = normalizeEmail(req.body.email);
  if (!norm) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (DISPOSABLE.has(norm.split('@')[1])) return res.status(400).json({ error: 'Please use a permanent email address.' });
  if (limited('oi:' + ipOf(req), 10, 60 * 60 * 1000) || limited('oe:' + norm, 5, 60 * 60 * 1000) || limited('oe1:' + norm, 1, 45 * 1000)) {
    return res.status(429).json({ error: 'Too many codes requested. Wait a minute and try again.' });
  }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  otpStore.set(norm, { hash: sha(code + norm + JWT_SECRET), exp: Date.now() + OTP_TTL_MS, attempts: 0 });

  const to = String(req.body.email).trim();
  try {
    if (transporter) {
      await transporter.sendMail({
        from: process.env.MAIL_FROM || process.env.SMTP_USER,
        to,
        subject: `Your ${APP_NAME} code: ${code}`,
        text: `Your ${APP_NAME} sign-in code is ${code}. It works for 10 minutes. If you did not ask for it, ignore this email.`,
      });
    } else {
      console.log(`[DEV OTP] ${to} -> ${code}`);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('[auth] mail error:', e.message);
    otpStore.delete(norm);
    res.status(500).json({ error: 'Could not send the email. Try again in a bit.' });
  }
});

router.post('/otp/verify', (req, res) => {
  const norm = normalizeEmail(req.body.email);
  const code = String(req.body.code || '').trim();
  if (!norm || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code.' });
  if (limited('v:' + ipOf(req), 30, 10 * 60 * 1000)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });

  const rec = otpStore.get(norm);
  if (!rec || rec.exp < Date.now()) { otpStore.delete(norm); return res.status(400).json({ error: 'Code expired. Ask for a new one.' }); }
  if (rec.attempts >= OTP_MAX_ATTEMPTS) { otpStore.delete(norm); return res.status(429).json({ error: 'Too many wrong tries. Ask for a new code.' }); }
  rec.attempts++;

  const given = Buffer.from(sha(code + norm + JWT_SECRET));
  const real = Buffer.from(rec.hash);
  if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) {
    return res.status(400).json({ error: 'Wrong code. Check and try again.' });
  }
  otpStore.delete(norm);
  res.json(issueSession(String(req.body.email).trim()));
});

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of otpStore) if (v.exp < now) otpStore.delete(k);
}, 5 * 60 * 1000).unref();

module.exports = { router, verifySession };
