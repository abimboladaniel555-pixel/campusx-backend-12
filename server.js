require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./db');

const app = express();
const SECRET = process.env.JWT_SECRET || 'dev-only-secret';
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Waits for the database to be set up before handling any request.
app.use(async (_req, res, next) => {
  try { await db.ready; next(); }
  catch (e) { res.status(500).json({ error: 'Database is not ready: ' + e.message }); }
});

/* ---------- helpers ---------- */
const h = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); // lets async routes report errors
const sign = u => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: '7d' });
const publicUser = u => ({ id: u.id, name: u.name, handle: u.handle, email: u.email, role: u.role, dept: u.dept, bio: u.bio, phone: u.phone });
const getSettings = async () => {
  const rows = await db.all('SELECT key, value FROM settings');
  return { ...db.DEFAULTS, ...Object.fromEntries(rows.map(r => [r.key, r.value])) };
};

function optionalAuth(req, _res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(t, SECRET); } catch { req.user = null; }
  next();
}
function requireAuth(req, res, next) {
  optionalAuth(req, res, () => req.user ? next() : res.status(401).json({ error: 'Please log in first.' }));
}
// Checks the role in the database, so removing someone's admin access takes effect straight away.
function requireAdmin(req, res, next) {
  requireAuth(req, res, async () => {
    try {
      const u = await db.get('SELECT role FROM users WHERE id = ?', [req.user.id]);
      u && u.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only.' });
    } catch (e) { next(e); }
  });
}

/* ---------- public settings (campus name, tips, categories...) ---------- */
app.get('/api/settings', h(async (_req, res) => res.json(await getSettings())));

/* ---------- auth ---------- */
app.post('/api/auth/register', h(async (req, res) => {
  const { name, handle, email, password } = req.body || {};
  if (!name || !handle || !email || !password || password.length < 8)
    return res.status(400).json({ error: 'Name, handle, email and a password of 8+ characters are required.' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const cleanEmail = email.trim().toLowerCase();
    const role = process.env.ADMIN_EMAIL && cleanEmail === process.env.ADMIN_EMAIL.trim().toLowerCase() ? 'admin' : 'student';
    const { id } = await db.run('INSERT INTO users (name, handle, email, password_hash, role) VALUES (?,?,?,?,?)',
      [name.trim(), handle.trim().toLowerCase(), cleanEmail, hash, role]);
    const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
    res.status(201).json({ token: sign(user), user: publicUser(user) });
  } catch (e) {
    res.status(409).json({ error: 'That email or handle is already taken.' });
  }
}));

app.post('/api/auth/login', h(async (req, res) => {
  const { email, password } = req.body || {};
  const user = await db.get('SELECT * FROM users WHERE email = ?', [(email || '').toLowerCase()]);
  if (!user || !bcrypt.compareSync(password || '', user.password_hash))
    return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign(user), user: publicUser(user) });
}));

app.get('/api/me', requireAuth, h(async (req, res) => {
  const u = await db.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!u) return res.status(401).json({ error: 'Please log in first.' });
  res.json(publicUser(u));
}));

app.put('/api/me', requireAuth, h(async (req, res) => {
  const { name, bio, dept, phone } = req.body || {};
  await db.run('UPDATE users SET name = COALESCE(?, name), bio = COALESCE(?, bio), dept = COALESCE(?, dept), phone = COALESCE(?, phone) WHERE id = ?',
    [name ?? null, bio ?? null, dept ?? null, phone ?? null, req.user.id]);
  res.json(publicUser(await db.get('SELECT * FROM users WHERE id = ?', [req.user.id])));
}));

/* ---------- feed ---------- */
app.get('/api/posts', optionalAuth, h(async (req, res) => {
  const rows = await db.all(`
    SELECT p.id, p.anon, p.text, p.tags, p.created_at,
      CASE WHEN p.anon = 1 THEN 'Anonymous Student' ELSE u.name END AS name,
      (SELECT COUNT(*) FROM post_likes l WHERE l.post_id = p.id) AS likes,
      EXISTS (SELECT 1 FROM post_likes l WHERE l.post_id = p.id AND l.user_id = ?) AS liked
    FROM posts p JOIN users u ON u.id = p.user_id
    ORDER BY p.id DESC LIMIT 50`, [req.user?.id || 0]);
  res.json(rows.map(r => ({ ...r, anon: !!r.anon, liked: !!r.liked, tags: r.tags ? r.tags.split(' ') : [] })));
}));

app.post('/api/posts', requireAuth, h(async (req, res) => {
  const text = (req.body?.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Post text is required.' });
  const tags = (text.match(/#\w+/g) || []).join(' ');
  const { id } = await db.run('INSERT INTO posts (user_id, anon, text, tags) VALUES (?,?,?,?)',
    [req.user.id, req.body.anon ? 1 : 0, text.slice(0, 1000), tags]);
  res.status(201).json({ id });
}));

app.post('/api/posts/:id/like', requireAuth, h(async (req, res) => {
  const args = [req.params.id, req.user.id];
  const had = (await db.run('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?', args)).changes;
  if (!had) await db.run('INSERT INTO post_likes (post_id, user_id) VALUES (?,?)', args);
  res.json({ liked: !had });
}));

/* ---------- poll ---------- */
app.get('/api/poll', optionalAuth, h(async (req, res) => {
  const poll = await db.get('SELECT * FROM polls WHERE active = 1 ORDER BY id DESC LIMIT 1');
  if (!poll) return res.json(null);
  const opts = await db.all(`SELECT o.id, o.text, (SELECT COUNT(*) FROM poll_votes v WHERE v.option_id = o.id) AS votes
                             FROM poll_options o WHERE o.poll_id = ?`, [poll.id]);
  const mine = req.user ? await db.get('SELECT option_id FROM poll_votes WHERE poll_id = ? AND user_id = ?', [poll.id, req.user.id]) : null;
  res.json({ id: poll.id, question: poll.question, options: opts, votedOption: mine?.option_id ?? null });
}));

app.post('/api/poll/vote', requireAuth, h(async (req, res) => {
  const { pollId, optionId } = req.body || {};
  try { await db.run('INSERT INTO poll_votes (poll_id, user_id, option_id) VALUES (?,?,?)', [pollId, req.user.id, optionId]); res.json({ ok: true }); }
  catch { res.status(409).json({ error: 'You already voted in this poll.' }); }
}));

/* ---------- marketplace ---------- */
app.get('/api/listings', h(async (req, res) => {
  const { q = '', cat = '' } = req.query;
  res.json(await db.all(`
    SELECT l.id, l.title, l.price, l.cond, l.cat, l.location, l.phone, l.icon, u.name AS seller
    FROM listings l JOIN users u ON u.id = l.user_id
    WHERE l.status = 'active' AND l.title LIKE ? AND (? = '' OR l.cat = ?)
    ORDER BY l.id DESC LIMIT 100`, [`%${q}%`, cat, cat]));
}));

app.post('/api/listings', requireAuth, h(async (req, res) => {
  const { title, price, cat, phone, cond, location, icon } = req.body || {};
  const digits = String(phone || '').replace(/\D/g, '');
  if (!title || !(price > 0) || !cat || digits.length < 10)
    return res.status(400).json({ error: 'Title, price, category and a valid WhatsApp number are required.' });
  const loc = location || (await getSettings()).default_location;
  const { id } = await db.run('INSERT INTO listings (user_id, title, price, cond, cat, location, phone, icon) VALUES (?,?,?,?,?,?,?,?)',
    [req.user.id, title.trim(), Math.round(price), cond || 'Good', cat, loc, digits, icon || '📦']);
  res.status(201).json({ id });
}));

app.get('/api/my/listings', requireAuth, h(async (req, res) =>
  res.json(await db.all("SELECT * FROM listings WHERE user_id = ? AND status != 'removed' ORDER BY id DESC", [req.user.id]))));

app.delete('/api/listings/:id', requireAuth, h(async (req, res) => {
  const r = await db.run("UPDATE listings SET status = 'removed' WHERE id = ? AND user_id = ?", [req.params.id, req.user.id]);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Listing not found.' });
}));

/* ---------- academics ---------- */
app.get('/api/courses', requireAuth, h(async (req, res) =>
  res.json(await db.all('SELECT code, name, unit, grade FROM courses WHERE user_id = ? ORDER BY id', [req.user.id]))));

app.put('/api/courses', requireAuth, h(async (req, res) => {
  const list = Array.isArray(req.body) ? req.body : [];
  await db.batch([
    ['DELETE FROM courses WHERE user_id = ?', [req.user.id]],
    ...list.map(c => ['INSERT INTO courses (user_id, code, name, unit, grade) VALUES (?,?,?,?,?)',
      [req.user.id, String(c.code).slice(0, 20), String(c.name || '').slice(0, 100), +c.unit, +c.grade]])
  ]);
  res.json({ ok: true });
}));

app.get('/api/papers', h(async (_req, res) =>
  res.json(await db.all('SELECT id, title, meta, url FROM papers WHERE active = 1 ORDER BY id'))));

/* ================= ADMIN ================= */
app.get('/api/admin/stats', requireAdmin, h(async (_req, res) => res.json({
  users: (await db.get('SELECT COUNT(*) c FROM users')).c,
  posts: (await db.get('SELECT COUNT(*) c FROM posts')).c,
  listings: (await db.get("SELECT COUNT(*) c FROM listings WHERE status = 'active'")).c
})));

/* settings: edit the campus name, tips, categories and other site text */
app.get('/api/admin/settings', requireAdmin, h(async (_req, res) => res.json(await getSettings())));
app.put('/api/admin/settings', requireAdmin, h(async (req, res) => {
  const entries = Object.entries(req.body || {}).filter(([k]) => k in db.DEFAULTS);
  if (!entries.length) return res.status(400).json({ error: 'Nothing to save.' });
  await db.batch(entries.map(([k, v]) => ['INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', [k, String(v).slice(0, 500)]]));
  res.json(await getSettings());
}));

/* students */
app.get('/api/admin/users', requireAdmin, h(async (_req, res) =>
  res.json(await db.all('SELECT id, name, handle, email, role, dept FROM users ORDER BY id DESC'))));
app.put('/api/admin/users/:id', requireAdmin, h(async (req, res) => {
  const { name, role, dept } = req.body || {};
  if (role && !['student', 'admin'].includes(role)) return res.status(400).json({ error: 'Role must be student or admin.' });
  if (role && +req.params.id === req.user.id && role !== 'admin') return res.status(400).json({ error: 'You cannot remove your own admin access.' });
  const r = await db.run('UPDATE users SET name = COALESCE(?, name), role = COALESCE(?, role), dept = COALESCE(?, dept) WHERE id = ?',
    [name?.trim() || null, role || null, dept ?? null, req.params.id]);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Student not found.' });
}));

/* posts */
app.get('/api/admin/posts', requireAdmin, h(async (_req, res) =>
  res.json(await db.all(`SELECT p.id, p.text, p.anon, p.created_at, u.name
    FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.id DESC LIMIT 100`))));
app.put('/api/admin/posts/:id', requireAdmin, h(async (req, res) => {
  const text = (req.body?.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Post text is required.' });
  const r = await db.run('UPDATE posts SET text = ?, tags = ? WHERE id = ?', [text.slice(0, 1000), (text.match(/#\w+/g) || []).join(' '), req.params.id]);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Post not found.' });
}));
app.delete('/api/admin/posts/:id', requireAdmin, h(async (req, res) => {
  await db.batch([['DELETE FROM post_likes WHERE post_id = ?', [req.params.id]], ['DELETE FROM posts WHERE id = ?', [req.params.id]]]);
  res.json({ ok: true });
}));

/* listings */
app.get('/api/admin/listings', requireAdmin, h(async (_req, res) =>
  res.json(await db.all(`SELECT l.id, l.title, l.price, l.cond, l.cat, l.location, l.status, u.name AS seller
    FROM listings l JOIN users u ON u.id = l.user_id ORDER BY l.id DESC LIMIT 100`))));
app.put('/api/admin/listings/:id', requireAdmin, h(async (req, res) => {
  const { title, price, location, cat, status } = req.body || {};
  if (status && !['active', 'sold', 'removed'].includes(status)) return res.status(400).json({ error: 'Status must be active, sold or removed.' });
  const r = await db.run('UPDATE listings SET title = COALESCE(?, title), price = COALESCE(?, price), location = COALESCE(?, location), cat = COALESCE(?, cat), status = COALESCE(?, status) WHERE id = ?',
    [title?.trim() || null, price > 0 ? Math.round(price) : null, location?.trim() || null, cat || null, status || null, req.params.id]);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Listing not found.' });
}));
app.delete('/api/admin/listings/:id', requireAdmin, h(async (req, res) => {
  const r = await db.run("UPDATE listings SET status = 'removed' WHERE id = ?", [req.params.id]);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'Listing not found.' });
}));

/* polls */
app.get('/api/admin/polls', requireAdmin, h(async (_req, res) => {
  const polls = await db.all('SELECT id, question, active FROM polls ORDER BY id DESC LIMIT 30');
  for (const p of polls)
    p.options = await db.all('SELECT o.id, o.text, (SELECT COUNT(*) FROM poll_votes v WHERE v.option_id = o.id) AS votes FROM poll_options o WHERE o.poll_id = ?', [p.id]);
  res.json(polls);
}));
app.post('/api/admin/poll', requireAdmin, h(async (req, res) => {
  const question = (req.body?.question || '').trim();
  const options = (req.body?.options || []).map(o => String(o).trim()).filter(Boolean);
  if (!question || options.length < 2) return res.status(400).json({ error: 'A question and at least 2 options are required.' });
  await db.run('UPDATE polls SET active = 0');
  const { id } = await db.run('INSERT INTO polls (question, active) VALUES (?, 1)', [question]);
  await db.batch(options.map(o => ['INSERT INTO poll_options (poll_id, text) VALUES (?, ?)', [id, o]]));
  res.status(201).json({ id });
}));
app.put('/api/admin/polls/:id', requireAdmin, h(async (req, res) => {
  const { question, active, options } = req.body || {};
  const stmts = [];
  if (active) stmts.push(['UPDATE polls SET active = 0', []]);
  if (question?.trim()) stmts.push(['UPDATE polls SET question = ? WHERE id = ?', [question.trim(), req.params.id]]);
  if (typeof active === 'boolean') stmts.push(['UPDATE polls SET active = ? WHERE id = ?', [active ? 1 : 0, req.params.id]]);
  (options || []).forEach(o => o.text?.trim() && stmts.push(['UPDATE poll_options SET text = ? WHERE id = ? AND poll_id = ?', [o.text.trim(), o.id, req.params.id]]));
  if (stmts.length) await db.batch(stmts);
  res.json({ ok: true });
}));
app.delete('/api/admin/polls/:id', requireAdmin, h(async (req, res) => {
  await db.batch([['DELETE FROM poll_votes WHERE poll_id = ?', [req.params.id]], ['DELETE FROM poll_options WHERE poll_id = ?', [req.params.id]], ['DELETE FROM polls WHERE id = ?', [req.params.id]]]);
  res.json({ ok: true });
}));

/* past questions and notes */
app.get('/api/admin/papers', requireAdmin, h(async (_req, res) => res.json(await db.all('SELECT * FROM papers ORDER BY id DESC'))));
app.post('/api/admin/papers', requireAdmin, h(async (req, res) => {
  const { title, meta, url } = req.body || {};
  if (!title?.trim()) return res.status(400).json({ error: 'A title is required.' });
  const { id } = await db.run('INSERT INTO papers (title, meta, url) VALUES (?,?,?)', [title.trim(), (meta || '').trim(), (url || '').trim()]);
  res.status(201).json({ id });
}));
app.put('/api/admin/papers/:id', requireAdmin, h(async (req, res) => {
  const { title, meta, url, active } = req.body || {};
  const r = await db.run('UPDATE papers SET title = COALESCE(?, title), meta = COALESCE(?, meta), url = COALESCE(?, url), active = COALESCE(?, active) WHERE id = ?',
    [title?.trim() || null, meta ?? null, url ?? null, typeof active === 'boolean' ? (active ? 1 : 0) : null, req.params.id]);
  r.changes ? res.json({ ok: true }) : res.status(404).json({ error: 'File entry not found.' });
}));
app.delete('/api/admin/papers/:id', requireAdmin, h(async (req, res) => { await db.run('DELETE FROM papers WHERE id = ?', [req.params.id]); res.json({ ok: true }); }));

/* ---------- errors + start ---------- */
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Server error: ' + err.message }); });

if (!process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`CampusX running at http://localhost:${PORT}`));
}
module.exports = app;
