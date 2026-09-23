// Random chat server (text + video signaling). App name comes from APP_NAME in .env
require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const { Server } = require('socket.io');
const moderation = require('./moderation');
const auth = require('./auth');
const translator = require('./translate');
const security = require('./security');
const profanity = require('./profanity');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5 });

app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use('/auth', auth.router);
app.use(express.static(path.join(__dirname, 'public')));
// On-device nudity model files (served from node_modules, no external CDN)
app.use('/vendor/tf', express.static(path.join(__dirname, 'node_modules/@tensorflow/tfjs/dist')));
app.use('/vendor/nsfw', express.static(path.join(__dirname, 'node_modules/nsfwjs/dist/browser')));
app.use('/vendor/nsfw-model', express.static(path.join(__dirname, 'node_modules/nsfwjs/dist/models/mobilenet_v2')));

const PORT = process.env.PORT || 3000;
const REPORTS_TO_BAN = 3;               // reports within 24h -> ban
const BAN_MS = 24 * 60 * 60 * 1000;     // 24 hour ban (change as you like)
const REPORT_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_MSG_LEN = 500;
const MSG_WINDOW_MS = 5000;
const MSG_MAX = 8;                      // max 8 messages per 5 seconds
// ---- Countries ----
// "Popular Countries" group (neutral label, avoids naming a disputed region): Brunei, China, Indonesia, Cambodia, Malaysia,
// Philippines, Singapore, Thailand, Taiwan, Vietnam
const SCS = ['BN', 'CN', 'ID', 'KH', 'MY', 'PH', 'SG', 'TH', 'TW', 'VN'];
const TRUST_CLOUDFLARE = process.env.TRUST_CLOUDFLARE === '1'; // set to 1 only if the site is behind Cloudflare
const cleanCountry = (c) => { c = String(c || '').toUpperCase(); return /^[A-Z]{2}$/.test(c) ? c : 'XX'; };
function cleanWant(w) {
  w = String(w || 'any');
  if (w === 'any' || w === 'scs') return w;
  const c = w.toUpperCase();
  return /^[A-Z]{2}$/.test(c) ? c : 'any';
}
const accepts = (want, country) => want === 'any' || (want === 'scs' ? SCS.includes(country) : want === country);

// ---- Live translation ----
const SUPPORTED_LANGS = ['vi','tl','ms','id','zh-CN','zh-TW','th','km','en','hi','bn','ta','te','mr','gu','kn','ml','pa','ur','ne','si','ja','ko','es','fr','de','pt','ru','ar','tr','it','nl','pl','uk','fa','he','sw','el','sv'];
const cleanLang = (l) => (SUPPORTED_LANGS.includes(l) ? l : 'en');
const DAILY_TRANSLATE_CHARS = parseInt(process.env.TRANSLATE_DAILY_CHARS || '60000', 10); // per account per day, protects your bill
const usage = new Map();
function withinQuota(uid, n) {
  const day = new Date().toISOString().slice(0, 10);
  const u = usage.get(uid);
  if (!u || u.day !== day) { if (n > DAILY_TRANSLATE_CHARS) return false; usage.set(uid, { day, chars: n }); return true; }
  if (u.chars + n > DAILY_TRANSLATE_CHARS) return false;
  u.chars += n;
  return true;
}
// Sends a message or spoken sentence to the partner, translated into their language when needed.
async function deliver(sender, partner, event, text) {
  const from = sender.data.lang;
  const to = partner.data.lang;
  let translated = null;
  let failed = false;
  if (from !== to) {
    try {
      if (!withinQuota(sender.data.uid, text.length)) throw new Error('quota');
      translated = await translator.translate(text, { from: event === 'speech' ? from : null, to });
    } catch (e) {
      failed = true;
    }
  }
  if (sender.data.partner !== partner.id) return; // partner left while we were translating
  partner.emit(event, { text, translated, from, failed });
}

// ---- Ban-evasion resistance: device fingerprint + VPN/proxy flag ----
// A fingerprint is a rough "signature" of the browser/device (screen size, timezone, fonts, etc.)
// It survives a new Google/Facebook/email login and clearing cookies, though not a fresh browser
// profile or a different device. Combined with the email + IP bans, it raises the bar for evasion
// without being airtight -- no fingerprinting system is.
const cleanFp = (fp) => { fp = String(fp || '').slice(0, 128); return /^[a-f0-9]{8,64}$/i.test(fp) ? fp : null; };
const TEXT_STRIKES_TO_BAN = 2;
const TEXT_BAN_MS = 24 * 60 * 60 * 1000;

const REPORTS_FILE = path.join(__dirname, 'reports.jsonl');

// ---- AI nudity moderation settings (override with environment variables) ----
const NSFW_THRESHOLD = parseFloat(process.env.NSFW_THRESHOLD || '0.75');      // server confirms nudity at this score
const NSFW_INSTANT_BAN = parseFloat(process.env.NSFW_INSTANT_BAN || '0.92');  // one hit this strong = permanent ban
const STRIKES_TO_BAN = 2;                                                     // otherwise ban on 2nd confirmed hit
const IP_BAN_MS = 7 * 24 * 60 * 60 * 1000;                                    // IP also blocked for 7 days
const REMOTE_BAN_COOLDOWN_MS = 10 * 60 * 1000;                                // limits abuse of false "remote" flags
const MOD_LOG = path.join(__dirname, 'moderation.jsonl');
const BANS_FILE = path.join(__dirname, 'bans.json');

let permBans = { uids: {}, ips: {}, fingerprints: {} };
try { permBans = JSON.parse(fs.readFileSync(BANS_FILE, 'utf8')); } catch (e) { /* first run */ }
if (!permBans.fingerprints) permBans.fingerprints = {};
function saveBans() {
  fs.writeFile(BANS_FILE, JSON.stringify(permBans, null, 1), () => {});
}

const bans = new Map();          // ip/uid -> banned until (ms)
const reportLog = new Map();     // ip/uid -> [timestamps]
let queue = [];                  // sockets waiting for a partner

function getIP(socket) {
  const xf = socket.handshake.headers['x-forwarded-for'];
  return (xf ? xf.split(',')[0].trim() : socket.handshake.address) || 'unknown';
}

function isBanned(s) {
  const now = Date.now();
  if (s.data.uid && permBans.uids[s.data.uid]) return true;
  if (s.data.fp && permBans.fingerprints[s.data.fp]) return true;
  if ((permBans.ips[s.data.ip] || 0) > now) return true;
  return [s.data.ip, s.data.uid, s.data.fp].some((k) => k && (bans.get(k) || 0) > now);
}

function leaveQueue(s) {
  queue = queue.filter((x) => x.id !== s.id);
}

function unpair(s, notify = true) {
  const pid = s.data.partner;
  s.data.partner = null;
  s.data.log = null;
  if (pid) {
    const p = io.sockets.sockets.get(pid);
    if (p) {
      p.data.partner = null;
      p.data.log = null;
      if (notify) p.emit('partner-left');
    }
  }
}

function compatible(a, b) {
  if (a.id === b.id) return false;
  if (a.data.uid === b.data.uid) return false;
  if (a.data.mode !== b.data.mode) return false;
  if (!accepts(a.data.want, b.data.country) || !accepts(b.data.want, a.data.country)) return false;
  if (a.data.blocked.has(b.data.uid) || b.data.blocked.has(a.data.uid)) return false;
  return true;
}

function common(a, b) {
  return a.data.interests.filter((i) => b.data.interests.includes(i));
}

function findMatch(s) {
  let best = null;
  let bestScore = -1;
  for (const c of queue) {
    if (!compatible(s, c)) continue;
    const score = common(s, c).length;
    if (score > bestScore) { best = c; bestScore = score; }
  }
  return best;
}

function pair(a, b) {
  const log = [];
  a.data.partner = b.id;
  b.data.partner = a.id;
  a.data.log = log;
  b.data.log = log;
  const shared = common(a, b);
  a.emit('matched', { initiator: true, common: shared, country: b.data.country, lang: b.data.lang });
  b.emit('matched', { initiator: false, common: shared, country: a.data.country, lang: a.data.lang });
}

function cleanInterests(list) {
  if (!Array.isArray(list)) return [];
  return [...new Set(list.map((i) => String(i).toLowerCase().trim().slice(0, 24)).filter(Boolean))].slice(0, 5);
}

// Only signed-in users can open a socket. The account id comes from the signed token,
// never from the browser, so bans cannot be dodged by clearing storage.
io.use((socket, next) => {
  const uid = auth.verifySession(socket.handshake.auth && socket.handshake.auth.token);
  if (!uid) return next(new Error('auth'));
  socket.authUid = uid;
  next();
});

io.on('connection', (socket) => {
  socket.data = {
    ip: getIP(socket),
    uid: socket.authUid,
    mode: 'text',
    interests: [],
    country: 'XX',
    want: 'any',
    lang: 'en',
    chain: Promise.resolve(),
    speechTimes: [],
    partner: null,
    strikes: 0,
    lastSuspect: 0,
    lastRemoteBan: 0,
    fp: null,
    vpn: false,
    textStrikes: 0,
    blocked: new Set(),
    log: null,
    msgTimes: [],
  };

  socket.on('join', (p = {}) => {
    if (p.adult !== true) return socket.emit('error-msg', 'You must confirm you are 18 or older.');
    socket.data.mode = p.mode === 'video' ? 'video' : 'text';
    socket.data.interests = cleanInterests(p.interests);
    const cf = String(socket.handshake.headers['cf-ipcountry'] || '').toUpperCase();
    socket.data.country = TRUST_CLOUDFLARE && /^[A-Z]{2}$/.test(cf) && cf !== 'XX' && cf !== 'T1' ? cf : cleanCountry(p.country);
    socket.data.want = cleanWant(p.want);
    socket.data.lang = cleanLang(p.lang);
    socket.data.fp = cleanFp(p.fp);
    if (isBanned(socket)) return socket.emit('banned', { permanent: !!(permBans.uids[socket.data.uid] || (socket.data.fp && permBans.fingerprints[socket.data.fp])) });
    // VPN/proxy check runs in the background; it only informs moderation logs and does not block anyone by itself.
    security.checkProxy(socket.data.ip).then((r) => { socket.data.vpn = r.isProxy; });

    unpair(socket);
    leaveQueue(socket);

    const match = findMatch(socket);
    if (match) {
      leaveQueue(match);
      pair(socket, match);
    } else {
      queue.push(socket);
      socket.emit('waiting');
    }
  });

  socket.on('leave', () => {
    leaveQueue(socket);
    unpair(socket);
  });

  socket.on('message', (text) => {
    const partner = socket.data.partner && io.sockets.sockets.get(socket.data.partner);
    if (!partner || typeof text !== 'string') return;
    const now = Date.now();
    socket.data.msgTimes = socket.data.msgTimes.filter((t) => now - t < MSG_WINDOW_MS);
    if (socket.data.msgTimes.length >= MSG_MAX) return socket.emit('error-msg', 'Slow down a little.');
    socket.data.msgTimes.push(now);
    const clean = text.slice(0, MAX_MSG_LEN);
    if (!clean.trim()) return;
    if (profanity.containsVulgarLanguage(clean)) return handleVulgar(socket, clean, 'text');
    if (socket.data.log) {
      socket.data.log.push({ t: now, from: socket.data.uid, text: clean });
      if (socket.data.log.length > 40) socket.data.log.shift();
    }
    socket.data.chain = socket.data.chain.then(() => deliver(socket, partner, 'message', clean));
  });

  // Spoken sentence (already turned into text by the speaker's browser)
  socket.on('speech', (text) => {
    const partner = socket.data.partner && io.sockets.sockets.get(socket.data.partner);
    if (!partner || typeof text !== 'string') return;
    const now = Date.now();
    socket.data.speechTimes = socket.data.speechTimes.filter((t) => now - t < MSG_WINDOW_MS);
    if (socket.data.speechTimes.length >= MSG_MAX) return;
    socket.data.speechTimes.push(now);
    const clean = text.trim().slice(0, 300);
    if (!clean) return;
    if (profanity.containsVulgarLanguage(clean)) return handleVulgar(socket, clean, 'voice');
    if (socket.data.log) {
      socket.data.log.push({ t: now, from: socket.data.uid, text: clean, voice: true });
      if (socket.data.log.length > 40) socket.data.log.shift();
    }
    socket.data.chain = socket.data.chain.then(() => deliver(socket, partner, 'speech', clean));
  });

  socket.on('typing', (isTyping) => {
    const partner = socket.data.partner && io.sockets.sockets.get(socket.data.partner);
    if (partner) partner.emit('typing', !!isTyping);
  });

  // WebRTC signaling relay (offer / answer / ICE candidates)
  socket.on('signal', (data) => {
    const partner = socket.data.partner && io.sockets.sockets.get(socket.data.partner);
    if (partner) partner.emit('signal', data);
  });

  socket.on('block', () => {
    const partner = socket.data.partner && io.sockets.sockets.get(socket.data.partner);
    if (partner) socket.data.blocked.add(partner.data.uid);
    unpair(socket);
  });

  socket.on('report', (reason) => {
    const partner = socket.data.partner && io.sockets.sockets.get(socket.data.partner);
    if (!partner) return;
    const now = Date.now();
    const entry = {
      time: new Date(now).toISOString(),
      reporter: socket.data.uid,
      reported: partner.data.uid,
      reportedIp: partner.data.ip,
      reason: String(reason || '').slice(0, 100),
      lastMessages: socket.data.log || [],
    };
    fs.appendFile(REPORTS_FILE, JSON.stringify(entry) + '\n', () => {});

    for (const key of [partner.data.ip, partner.data.uid]) {
      const list = (reportLog.get(key) || []).filter((t) => now - t < REPORT_WINDOW_MS);
      list.push(now);
      reportLog.set(key, list);
      if (list.length >= REPORTS_TO_BAN) bans.set(key, now + BAN_MS);
    }
    socket.data.blocked.add(partner.data.uid);
    const partnerBanned = isBanned(partner);
    unpair(socket, !partnerBanned);
    if (partnerBanned) partner.emit('banned');
  });

  function handleVulgar(socket, text, kind) {
    const now = Date.now();
    socket.data.textStrikes += 1;
    fs.appendFile(MOD_LOG, JSON.stringify({
      time: new Date(now).toISOString(), side: kind, action: 'vulgar-text',
      reporter: socket.data.uid, target: socket.data.uid, targetIp: socket.data.ip, vpn: socket.data.vpn, sample: text.slice(0, 60),
    }) + '\n', () => {});
    if (socket.data.textStrikes >= TEXT_STRIKES_TO_BAN) {
      for (const key of [socket.data.ip, socket.data.uid, socket.data.fp].filter(Boolean)) bans.set(key, now + TEXT_BAN_MS);
      socket.emit('banned', { permanent: false, reason: 'vulgar language' });
      unpair(socket, true);
    } else {
      socket.emit('warning', 'Vulgar or sexual language is not allowed here. One more time and you will be temporarily banned.');
    }
  }

  // AI nudity check: the client's on-device model flags a frame, the server verifies it.
  // side 'remote' = the frame shows my partner, side 'local' = the frame shows me.
  socket.on('suspect', async (p = {}) => {
    if (socket.data.mode !== 'video') return;
    const side = p.side === 'local' ? 'local' : 'remote';
    const now = Date.now();
    if (now - socket.data.lastSuspect < 1500) return;
    socket.data.lastSuspect = now;

    const partner = socket.data.partner && io.sockets.sockets.get(socket.data.partner);
    if (side === 'remote' && !partner) return;

    let scores;
    try {
      scores = await moderation.classifyFrame(p.frame);
    } catch (e) {
      return socket.emit('nsfw-verdict', { side, confirmed: false });
    }
    if (side === 'remote' && socket.data.partner !== (partner && partner.id)) return; // partner changed meanwhile

    const confirmed = scores.porn >= NSFW_THRESHOLD;
    socket.emit('nsfw-verdict', { side, confirmed });
    if (!confirmed) return;

    const target = side === 'local' ? socket : partner;
    const other = side === 'local' ? partner : socket;
    target.data.strikes += 1;
    const permanent = scores.porn >= NSFW_INSTANT_BAN || target.data.strikes >= STRIKES_TO_BAN;
    let action = 'warned';

    if (permanent) {
      if (side === 'remote' && now - socket.data.lastRemoteBan < REMOTE_BAN_COOLDOWN_MS) {
        action = 'held-for-review';
      } else {
        if (side === 'remote') socket.data.lastRemoteBan = now;
        permBans.uids[target.data.uid] = { time: new Date(now).toISOString(), reason: 'nudity', score: +scores.porn.toFixed(3), vpn: target.data.vpn };
        permBans.ips[target.data.ip] = now + IP_BAN_MS;
        if (target.data.fp) permBans.fingerprints[target.data.fp] = { time: new Date(now).toISOString(), reason: 'nudity' };
        saveBans();
        action = 'permanent-ban';
        target.emit('banned', { permanent: true });
        unpair(target, false);
        if (other) other.emit('partner-left');
      }
    }
    if (action === 'warned' || action === 'held-for-review') {
      target.emit('warning', 'Nudity is not allowed. Another violation means a permanent ban.');
    }

    // Log metadata only. Images are never stored.
    fs.appendFile(MOD_LOG, JSON.stringify({
      time: new Date(now).toISOString(), side, action,
      reporter: socket.data.uid, target: target.data.uid, targetIp: target.data.ip,
      porn: +scores.porn.toFixed(3), sexy: +(scores.Sexy || 0).toFixed(3),
    }) + '\n', () => {});
  });

  socket.on('disconnect', () => {
    leaveQueue(socket);
    unpair(socket);
  });
});

setInterval(() => io.emit('online', io.engine.clientsCount), 5000);

moderation.warmUp().then(() => console.log('AI nudity model ready')).catch((e) => console.error('AI model failed to load:', e.message));

server.listen(PORT, () => console.log(`${process.env.APP_NAME || 'GlobeTalk'} running on http://localhost:${PORT}`));
