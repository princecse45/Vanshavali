require('dotenv').config();
const express = require('express'), session = require('express-session'), bcrypt = require('bcryptjs');
const multer = require('multer'), Database = require('better-sqlite3');
const path = require('path'), fs = require('fs'), crypto = require('crypto');
const helmet = require('helmet'), rateLimit = require('express-rate-limit'), nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');

const MAX_ANCESTORS = 100; // ek user kitne ancestors daal sakta hai
const db = new Database('data.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, uid TEXT UNIQUE, name TEXT, email TEXT UNIQUE, pass TEXT);
CREATE TABLE IF NOT EXISTS ancestors(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, relation TEXT, photo TEXT);
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, from_id INTEGER, to_id INTEGER, status TEXT DEFAULT 'pending', UNIQUE(from_id,to_id));
`);
for (const sql of ['ALTER TABLE users ADD COLUMN google_id TEXT', 'ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0',
  'ALTER TABLE users ADD COLUMN vtoken TEXT', 'ALTER TABLE users ADD COLUMN rtoken TEXT', 'ALTER TABLE users ADD COLUMN rexp INTEGER',
  'ALTER TABLE ancestors ADD COLUMN parent_id INTEGER'])
  try { db.exec(sql); } catch {} // column pehle se ho to ignore
fs.mkdirSync('uploads', { recursive: true });

const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };
const upload = multer({
  storage: multer.diskStorage({ destination: 'uploads', filename: (q, f, cb) => cb(null, crypto.randomUUID() + EXT[f.mimetype]) }),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (q, f, cb) => cb(null, !!EXT[f.mimetype])
});

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", 'https://accounts.google.com'],
  frameSrc: ['https://accounts.google.com'],
  connectSrc: ["'self'", 'https://accounts.google.com'],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://accounts.google.com'],
  fontSrc: ['https://fonts.gstatic.com'],
  imgSrc: ["'self'", 'data:', 'https://*.googleusercontent.com'],
  'upgrade-insecure-requests': null
} }, crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' } }));
app.use('/api', rateLimit({ windowMs: 15 * 60e3, max: 1500 }));
const authLimit = rateLimit({ windowMs: 15 * 60e3, max: 15, message: { error: 'Bahut zyada koshish. 15 minute baad dobara try karein' } });
app.use(express.json());
app.use(session({ secret: process.env.SECRET || 'change-this-secret', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' } }));
app.use(express.static('public'));   // sirf HTML/CSS/JS public hai, uploads/ folder NAHI

const auth = (q, s, n) => q.session.user ? n() : s.status(401).json({ error: 'Pehle login karein' });
const ownerOf = uid => db.prepare('SELECT id FROM users WHERE uid=?').get(uid);
// Privacy rule: khud ka data ya accepted request wala hi dekh sakta hai
const can = (viewer, owner) => viewer === owner ||
  !!db.prepare("SELECT 1 FROM requests WHERE from_id=? AND to_id=? AND status='accepted'").get(viewer, owner);

const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const APP_URL = process.env.APP_URL || 'http://localhost:3000';
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } }) : null;
async function sendMail(to, subject, text) {
  if (!mailer) return console.log(`\n[DEV MAIL to ${to}] ${subject}\n${text}\n`); // SMTP nahi hai to console mein dikhega
  await mailer.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to, subject, text });
}
const gClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const newUid = () => 'VN' + crypto.randomBytes(3).toString('hex').toUpperCase();
const loginAs = (q, u) => { q.session.user = u.id; return { uid: u.uid, name: u.name }; };

app.get('/api/config', (q, s) => s.json({ googleClientId: process.env.GOOGLE_CLIENT_ID || null }));

app.post('/api/register', authLimit, async (q, s) => {
  const { name, email, password } = q.body;
  if (!name || !email || !password || password.length < 6) return s.status(400).json({ error: 'Sab fields bharein (password kam se kam 6 akshar)' });
  const tok = crypto.randomBytes(24).toString('hex');
  try {
    db.prepare('INSERT INTO users(uid,name,email,pass,verified,vtoken) VALUES(?,?,?,?,0,?)')
      .run(newUid(), name.trim().slice(0, 60), email.toLowerCase().trim(), bcrypt.hashSync(password, 10), sha(tok));
  } catch { return s.status(400).json({ error: 'Ye email pehle se registered hai' }); }
  await sendMail(email, 'Vanshavali: email verify karein', `Email verify karne ke liye link kholein:\n${APP_URL}/api/verify?token=${tok}`).catch(console.error);
  s.json({ message: 'Verification link aapke email par bheja gaya hai. Verify karke login karein.' });
});
app.get('/api/verify', (q, s) => {
  const r = db.prepare('UPDATE users SET verified=1,vtoken=NULL WHERE vtoken=?').run(sha(String(q.query.token || '')));
  s.redirect('/?verified=' + (r.changes ? 1 : 0));
});
app.post('/api/login', authLimit, (q, s) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get((q.body.email || '').toLowerCase().trim());
  if (!u || !u.pass || !bcrypt.compareSync(q.body.password || '', u.pass)) return s.status(400).json({ error: 'Email ya password galat hai' });
  if (!u.verified) return s.status(403).json({ error: 'Pehle email verify karein (inbox/spam dekhein)' });
  s.json(loginAs(q, u));
});
app.post('/api/google', authLimit, async (q, s) => {
  try {
    const p = (await gClient.verifyIdToken({ idToken: q.body.credential, audience: process.env.GOOGLE_CLIENT_ID })).getPayload();
    if (!p.email_verified) return s.status(400).json({ error: 'Google email verified nahi hai' });
    const email = p.email.toLowerCase();
    let u = db.prepare('SELECT * FROM users WHERE google_id=? OR email=?').get(p.sub, email);
    if (!u) {
      const r = db.prepare('INSERT INTO users(uid,name,email,google_id,verified) VALUES(?,?,?,?,1)').run(newUid(), (p.name || 'User').slice(0, 60), email, p.sub);
      u = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
    } else db.prepare('UPDATE users SET google_id=?,verified=1 WHERE id=?').run(p.sub, u.id);
    s.json(loginAs(q, u));
  } catch { s.status(400).json({ error: 'Google login nahi ho paya' }); }
});
app.post('/api/forgot', authLimit, async (q, s) => {
  const email = (q.body.email || '').toLowerCase().trim(), tok = crypto.randomBytes(24).toString('hex');
  const r = db.prepare('UPDATE users SET rtoken=?,rexp=? WHERE email=?').run(sha(tok), Date.now() + 3600e3, email);
  if (r.changes) await sendMail(email, 'Vanshavali: password reset', `Naya password set karne ke liye (1 ghante mein expire):\n${APP_URL}/?reset=${tok}`).catch(console.error);
  s.json({ message: 'Agar ye email registered hai to reset link bhej diya gaya hai' });
});
app.post('/api/reset', authLimit, (q, s) => {
  if (!q.body.password || q.body.password.length < 6) return s.status(400).json({ error: 'Password kam se kam 6 akshar ka ho' });
  const r = db.prepare('UPDATE users SET pass=?,rtoken=NULL,rexp=NULL,verified=1 WHERE rtoken=? AND rexp>?')
    .run(bcrypt.hashSync(q.body.password, 10), sha(String(q.body.token || '')), Date.now());
  r.changes ? s.json({ ok: 1 }) : s.status(400).json({ error: 'Link galat ya expire ho gaya' });
});
app.post('/api/logout', (q, s) => q.session.destroy(() => s.json({ ok: 1 })));
app.get('/api/me', auth, (q, s) => s.json(db.prepare('SELECT uid,name FROM users WHERE id=?').get(q.session.user)));

// PUBLIC: sirf naam + ID. Ancestors yahan kabhi nahi aate.
app.get('/api/users', (q, s) => {
  const t = '%' + (q.query.q || '') + '%', v = q.session.user || 0;
  s.json(db.prepare(`SELECT u.uid,u.name,(SELECT status FROM requests WHERE from_id=? AND to_id=u.id) status
    FROM users u WHERE u.id!=? AND (u.name LIKE ? OR u.uid LIKE ?) LIMIT 50`).all(v, v, t, t));
});

app.get('/api/ancestors/:uid', auth, (q, s) => {
  const o = ownerOf(q.params.uid);
  if (!o || !can(q.session.user, o.id)) return s.status(403).json({ error: 'Access nahi hai. Pehle request bhejein aur accept hone ka wait karein.' });
  s.json(db.prepare('SELECT id,name,relation,parent_id,photo IS NOT NULL AS has_photo FROM ancestors WHERE user_id=? ORDER BY id').all(o.id));
});
app.get('/api/photo/:id', auth, (q, s) => {   // photo bhi protected hai
  const a = db.prepare('SELECT user_id,photo FROM ancestors WHERE id=?').get(q.params.id);
  if (!a || !a.photo || !can(q.session.user, a.user_id)) return s.sendStatus(404);
  s.sendFile(path.resolve('uploads', a.photo));
});
app.post('/api/ancestors', auth, upload.single('photo'), (q, s) => {
  const name = (q.body.name || '').trim();
  const drop = () => q.file && fs.unlink(q.file.path, () => {});
  if (!name) { drop(); return s.status(400).json({ error: 'Naam zaroori hai' }); }
  const parent = q.body.parent_id && db.prepare('SELECT id FROM ancestors WHERE id=? AND user_id=?').get(q.body.parent_id, q.session.user)?.id || null;
  const c = db.prepare('SELECT COUNT(*) c FROM ancestors WHERE user_id=?').get(q.session.user).c;
  if (c >= MAX_ANCESTORS) { drop(); return s.status(400).json({ error: `Maximum ${MAX_ANCESTORS} ancestors hi jod sakte hain` }); }
  db.prepare('INSERT INTO ancestors(user_id,name,relation,photo,parent_id) VALUES(?,?,?,?,?)')
    .run(q.session.user, name.slice(0, 80), (q.body.relation || '').trim().slice(0, 40), q.file ? q.file.filename : null, parent);
  s.json({ ok: 1 });
});
app.delete('/api/ancestors/:id', auth, (q, s) => {
  const a = db.prepare('SELECT photo FROM ancestors WHERE id=? AND user_id=?').get(q.params.id, q.session.user);
  if (!a) return s.sendStatus(404);
  if (a.photo) fs.unlink(path.resolve('uploads', a.photo), () => {});
  db.prepare('UPDATE ancestors SET parent_id=NULL WHERE parent_id=?').run(q.params.id);
  db.prepare('DELETE FROM ancestors WHERE id=?').run(q.params.id); s.json({ ok: 1 });
});

app.post('/api/request/:uid', auth, (q, s) => {
  const o = ownerOf(q.params.uid);
  if (!o || o.id === q.session.user) return s.status(400).json({ error: 'Galat user' });
  db.prepare('INSERT OR IGNORE INTO requests(from_id,to_id) VALUES(?,?)').run(q.session.user, o.id); s.json({ ok: 1 });
});
app.get('/api/requests', auth, (q, s) => s.json(db.prepare(
  "SELECT r.id,u.uid,u.name FROM requests r JOIN users u ON u.id=r.from_id WHERE r.to_id=? AND r.status='pending'").all(q.session.user)));
app.post('/api/requests/:id/:action', auth, (q, s) => {
  const st = { accept: 'accepted', reject: 'rejected' }[q.params.action];
  if (!st) return s.sendStatus(400);
  db.prepare('UPDATE requests SET status=? WHERE id=? AND to_id=?').run(st, q.params.id, q.session.user); s.json({ ok: 1 });
});

app.use((e, q, s, n) => s.status(400).json({ error: e.message })); // upload errors
app.listen(process.env.PORT || 3000, () => console.log('Chalu: http://localhost:' + (process.env.PORT || 3000)));
