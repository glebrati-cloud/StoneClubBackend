const express = require('express');
const session = require('express-session');
const cors = require('cors');
const helmet = require('helmet');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

// Data persistence
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const STONES_FILE = path.join(DATA_DIR, 'stones.json');
const PROMO_FILE = path.join(DATA_DIR, 'promos.json');

function loadJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

let users = loadJSON(USERS_FILE, []);
let stones = loadJSON(STONES_FILE, []);
let promos = loadJSON(PROMO_FILE, [
  { code: 'STONECLUB10', discountType: 'percent', discountValue: 10, bonusXp: 50, creatorName: 'StoneClub', active: true },
  { code: 'WHALE50', discountType: 'percent', discountValue: 50, bonusXp: 500, creatorName: 'StoneClub', active: true },
]);

// Initialize 1000 stones if empty
if (stones.length === 0) {
  const GEM_POOL = [
    { name: 'Obsidian', rarity: 'common' }, { name: 'Granite', rarity: 'common' },
    { name: 'Quartz', rarity: 'common' }, { name: 'Marble', rarity: 'common' },
    { name: 'Jade', rarity: 'uncommon' }, { name: 'Amethyst', rarity: 'uncommon' },
    { name: 'Topaz', rarity: 'uncommon' }, { name: 'Sapphire', rarity: 'rare' },
    { name: 'Ruby', rarity: 'rare' }, { name: 'Emerald', rarity: 'rare' },
    { name: 'Diamond', rarity: 'epic' }, { name: 'Opal', rarity: 'epic' },
    { name: 'Alexandrite', rarity: 'legendary' },
  ];
  const weights = { common: 40, uncommon: 25, rare: 20, epic: 12, legendary: 3 };
  const pool = [];
  GEM_POOL.forEach(g => { for (let i = 0; i < weights[g.rarity]; i++) pool.push(g); });

  for (let i = 1; i <= 1000; i++) {
    const gem = pool[Math.floor(Math.random() * pool.length)];
    stones.push({ id: i, number: i, gemName: gem.name, rarity: gem.rarity, ownerId: null, purchasedAt: null });
  }
  saveJSON(STONES_FILE, stones);
}

// XP Packs
const VALID_PACKS = ['spark', 'pebble', 'shard', 'fragment', 'chunk', 'boulder', 'monolith', 'obelisk', 'whale'];
const XP_PACKS = {
  spark: 50, pebble: 150, shard: 500, fragment: 1500, chunk: 5000,
  boulder: 15000, monolith: 50000, obelisk: 150000, whale: 500000,
};

// Titles by XP
function titleForXP(xp) {
  if (xp >= 500000) return 'Mythic';
  if (xp >= 150000) return 'Legendary';
  if (xp >= 50000) return 'Epic';
  if (xp >= 15000) return 'Rare';
  if (xp >= 5000) return 'Uncommon';
  if (xp >= 1500) return 'Common';
  if (xp >= 500) return 'Apprentice';
  if (xp >= 150) return 'Initiate';
  if (xp >= 50) return 'Newcomer';
  return 'Unranked';
}

// Custom rate limiter
function createRateLimiter(windowMs, maxReqs) {
  const hits = new Map();
  setInterval(() => hits.clear(), windowMs);
  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress;
    const current = hits.get(key) || 0;
    if (current >= maxReqs) {
      return res.status(429).json({ error: 'Too many requests. Try again later.' });
    }
    hits.set(key, current + 1);
    next();
  };
}

const generalLimiter = createRateLimiter(60000, 60);
const authLimiter = createRateLimiter(60000, 10);
const purchaseLimiter = createRateLimiter(60000, 15);

// Input validation
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const PROMO_RE = /^[A-Z0-9_]{3,30}$/;

function validateUsername(u) {
  return typeof u === 'string' && USERNAME_RE.test(u);
}
function validatePromoCode(c) {
  return typeof c === 'string' && PROMO_RE.test(c.toUpperCase());
}
function allowOnly(body, allowed) {
  const extra = Object.keys(body).filter(k => !allowed.includes(k));
  return extra.length === 0;
}

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST'],
}));
app.use(express.json({ limit: '16kb' }));

// Content-Type check (only when body present)
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const len = parseInt(req.headers['content-length'] || '0', 10);
    if (len > 0 && !req.is('json')) {
      return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
  }
  next();
});

app.use(generalLimiter);

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  name: 'sc_sid',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000,
  },
}));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// Health
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// Register
app.post('/api/register', authLimiter, (req, res) => {
  if (!allowOnly(req.body || {}, ['username'])) return res.status(400).json({ error: 'Unexpected fields' });
  const { username } = req.body || {};
  if (!validateUsername(username)) return res.status(400).json({ error: 'Username must be 3-20 alphanumeric chars or underscores' });
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'Username taken' });
  }
  const user = {
    id: users.length + 1,
    username,
    xp: 0,
    title: 'Unranked',
    stoneId: null,
    memberNumber: users.length + 1,
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  saveJSON(USERS_FILE, users);
  req.session.userId = user.id;
  res.status(201).json(user);
});

// Login
app.post('/api/login', authLimiter, (req, res) => {
  if (!allowOnly(req.body || {}, ['username'])) return res.status(400).json({ error: 'Unexpected fields' });
  const { username } = req.body || {};
  if (!validateUsername(username)) return res.status(400).json({ error: 'Invalid username format' });
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(404).json({ error: 'User not found' });

  const oldSession = req.session;
  req.session.regenerate((err) => {
    if (err) {
      console.error('Session regenerate error:', err);
      return res.status(500).json({ error: 'Session error' });
    }
    req.session.userId = user.id;
    const stone = stones.find(s => Number(s.ownerId) === Number(user.id));
    res.json({ ...user, stoneId: stone ? stone.id : null });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

// Profile
app.get('/api/profile', requireAuth, (req, res) => {
  const user = users.find(u => Number(u.id) === Number(req.session.userId));
  if (!user) return res.status(404).json({ error: 'User not found' });
  const stone = stones.find(s => Number(s.ownerId) === Number(user.id));
  res.json({ ...user, stoneId: stone ? stone.id : null });
});

// Stones remaining
app.get('/api/stones/remaining', (req, res) => {
  const claimed = stones.filter(s => s.ownerId !== null).length;
  res.json({ remaining: stones.length - claimed, total: stones.length, claimed });
});

// Claim stone
app.post('/api/stones/claim', requireAuth, (req, res) => {
  if (!allowOnly(req.body || {}, ['promoCode'])) return res.status(400).json({ error: 'Unexpected fields' });
  const userId = Number(req.session.userId);
  const user = users.find(u => Number(u.id) === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const existingStone = stones.find(s => Number(s.ownerId) === userId);
  if (existingStone) return res.status(409).json({ error: 'You already own a stone' });

  const available = stones.filter(s => s.ownerId === null);
  if (available.length === 0) return res.status(410).json({ error: 'All stones claimed' });

  const stone = available[Math.floor(Math.random() * available.length)];
  stone.ownerId = userId;
  stone.purchasedAt = new Date().toISOString();
  saveJSON(STONES_FILE, stones);

  res.json(stone);
});

// Vault
app.get('/api/vault', (req, res) => {
  const enriched = stones.map(s => {
    const owner = s.ownerId ? users.find(u => Number(u.id) === Number(s.ownerId)) : null;
    return {
      ...s,
      ownerUsername: owner?.username || null,
      ownerXp: owner?.xp || null,
      ownerTitle: owner?.title || null,
      ownerMemberNumber: owner?.memberNumber || null,
    };
  });
  const claimed = stones.filter(s => s.ownerId !== null).length;
  res.json({ stones: enriched, claimed, total: stones.length });
});

// Stone detail
app.get('/api/stones/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid stone ID' });
  const stone = stones.find(s => Number(s.id) === id);
  if (!stone) return res.status(404).json({ error: 'Stone not found' });
  const owner = stone.ownerId ? users.find(u => Number(u.id) === Number(stone.ownerId)) : null;
  res.json({
    ...stone,
    ownerUsername: owner?.username || null,
    ownerXp: owner?.xp || null,
    ownerTitle: owner?.title || null,
    ownerMemberNumber: owner?.memberNumber || null,
  });
});

// Leaderboard
app.get('/api/leaderboard', (req, res) => {
  const ranked = [...users]
    .sort((a, b) => b.xp - a.xp)
    .slice(0, 100)
    .map((u, i) => {
      const stone = stones.find(s => Number(s.ownerId) === Number(u.id));
      return {
        rank: i + 1,
        userId: u.id,
        username: u.username,
        xp: u.xp,
        title: u.title,
        gemName: stone?.gemName || null,
        rarity: stone?.rarity || null,
        stoneNumber: stone?.number || null,
        memberNumber: u.memberNumber,
      };
    });
  const currentUserId = req.session.userId ? Number(req.session.userId) : null;
  res.json({ entries: ranked, currentUserId });
});

// Purchase XP
app.post('/api/purchase-xp', requireAuth, purchaseLimiter, (req, res) => {
  if (!allowOnly(req.body || {}, ['pack'])) return res.status(400).json({ error: 'Unexpected fields' });
  const { pack } = req.body || {};
  if (!pack || !VALID_PACKS.includes(pack)) {
    return res.status(400).json({ error: 'Invalid pack. Valid: ' + VALID_PACKS.join(', ') });
  }
  const userId = Number(req.session.userId);
  const user = users.find(u => Number(u.id) === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const xpAdded = XP_PACKS[pack];
  user.xp += xpAdded;
  user.title = titleForXP(user.xp);
  saveJSON(USERS_FILE, users);

  res.json({ xpAdded, totalXp: user.xp, newTitle: user.title, pack });
});

// Verify promo
app.post('/api/promo/verify', requireAuth, (req, res) => {
  if (!allowOnly(req.body || {}, ['code'])) return res.status(400).json({ error: 'Unexpected fields' });
  const { code } = req.body || {};
  if (!code || !validatePromoCode(code)) return res.status(400).json({ error: 'Invalid promo code format' });

  const promo = promos.find(p => p.code === code.toUpperCase() && p.active);
  if (!promo) return res.json({ valid: false, code: code.toUpperCase(), bonusXp: 0, finalPrice: 0 });

  res.json({
    valid: true,
    code: promo.code,
    discountType: promo.discountType,
    discountValue: promo.discountValue,
    bonusXp: promo.bonusXp,
    creatorName: promo.creatorName,
    finalPrice: 0,
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Start
app.listen(PORT, '0.0.0.0', () => {
  console.log('Stone Club API running on port ' + PORT);
  console.log('Environment: ' + (process.env.NODE_ENV || 'development'));
});
