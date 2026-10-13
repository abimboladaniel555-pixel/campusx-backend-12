require('dotenv').config();
const { createClient } = require('@libsql/client');

// Uses Turso when TURSO_URL is set, otherwise a local file so you can test on your laptop.
const client = createClient({
  url: process.env.TURSO_URL || 'file:local.db',
  authToken: process.env.TURSO_TOKEN
});

// Every setting the admin page can edit, with its starting value.
const DEFAULTS = {
  app_name: 'CampusX',
  campus_name: 'UNILAG (Akoka)',
  campus_tag: 'UNILAG',
  feed_name: 'Akoka Buzz',
  compose_placeholder: 'Abeg drop the gist or confession...',
  announcement: '',
  default_location: 'UNILAG',
  categories: 'Phones,Laptops,Books,Hostel',
  market_badge: '0% commission',
  market_headline: 'Your Campus Plug 🔌',
  market_tagline: 'Sell unused gear to verified coursemates.',
  safe_tip: 'Inspect items and meet at well-lit hubs like the SUB or Main Library foyer in daylight. Never send advance fees.'
};

async function all(sql, args = []) {
  const r = await client.execute({ sql, args });
  return r.rows.map(row => Object.fromEntries(r.columns.map((c, i) => [c, row[i]])));
}
async function get(sql, args = []) { return (await all(sql, args))[0]; }
async function run(sql, args = []) {
  const r = await client.execute({ sql, args });
  return { changes: r.rowsAffected, id: Number(r.lastInsertRowid ?? 0) };
}
// Runs several statements together: all succeed or none do.
const batch = stmts => client.batch(stmts.map(([sql, args = []]) => ({ sql, args })), 'write');

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, handle TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student', dept TEXT NOT NULL DEFAULT '', bio TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, anon INTEGER NOT NULL DEFAULT 0, text TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS post_likes (post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY (post_id, user_id))`,
  `CREATE TABLE IF NOT EXISTS polls (id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS poll_options (id INTEGER PRIMARY KEY AUTOINCREMENT, poll_id INTEGER NOT NULL, text TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS poll_votes (poll_id INTEGER NOT NULL, user_id INTEGER NOT NULL, option_id INTEGER NOT NULL, PRIMARY KEY (poll_id, user_id))`,
  `CREATE TABLE IF NOT EXISTS listings (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, price INTEGER NOT NULL, cond TEXT NOT NULL DEFAULT 'Good', cat TEXT NOT NULL, location TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL, icon TEXT NOT NULL DEFAULT '📦', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS courses (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, code TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', unit INTEGER NOT NULL, grade INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS papers (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '', url TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1)`,
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`
];

async function init() {
  await client.batch(SCHEMA, 'write');
  await batch(Object.entries(DEFAULTS).map(([k, v]) => ['INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', [k, v]]));
  if ((await get('SELECT COUNT(*) AS c FROM papers')).c === 0) {
    await batch([
      ['INSERT INTO papers (title, meta) VALUES (?, ?)', ['MTH 101 Past Questions (2018-2023)', 'General Math • 14.2 MB • Solved CBT']],
      ['INSERT INTO papers (title, meta) VALUES (?, ?)', ['GST 102 Summary Notes & Cheat Sheet', 'Philosophy & Logic • 4.8 MB']],
      ['INSERT INTO papers (title, meta) VALUES (?, ?)', ['CHM 101 General Chemistry CBT Drill', '500 Mock Questions']],
      ['INSERT INTO papers (title, meta) VALUES (?, ?)', ['CPE 401 Signals & Systems Notes', 'Engineering • 9.1 MB']]
    ]);
  }
  // The account with this email is always an admin.
  if (process.env.ADMIN_EMAIL)
    await run("UPDATE users SET role = 'admin' WHERE email = ?", [process.env.ADMIN_EMAIL.trim().toLowerCase()]);
}
const ready = init();
ready.catch(e => console.error('Database setup failed:', e.message)); // keeps Node from crashing; requests report the error

module.exports = { all, get, run, batch, ready, DEFAULTS };
