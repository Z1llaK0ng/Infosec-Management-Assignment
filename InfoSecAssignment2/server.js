const crypto = require('crypto');
const path = require('path');
const express = require('express');
const session = require('express-session');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const db = require('./db');

const RP_ID = 'localhost';
const RP_NAME = 'Student Records Portal';
const ORIGIN = 'http://localhost:3000';

const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');
const safeEqual = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

const app = express();
app.use(express.json());
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 },
}));
app.use(express.static('public'));
app.get('/vendor/webauthn-browser.js', (req, res) =>
  res.sendFile(path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js')));

app.post('/api/register/options', async (req, res) => {
  const { userId, code } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(String(userId));
  const ok = user && !user.enrol_used && typeof code === 'string' &&
    safeEqual(hash(code), user.enrol_code_hash);
  if (!ok) return res.status(403).json({ error: 'Invalid enrolment details' });

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.id,
    userDisplayName: user.name,
    userID: new TextEncoder().encode(user.id),
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  req.session.reg = { userId: user.id, challenge: options.challenge };
  res.json(options);
});

app.post('/api/register/verify', async (req, res) => {
  const pending = req.session.reg;
  delete req.session.reg;
  if (!pending) return res.status(400).json({ error: 'No registration in progress' });

  let result;
  try {
    result = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
  } catch {
    return res.status(400).json({ error: 'Registration failed' });
  }
  if (!result.verified) return res.status(400).json({ error: 'Registration failed' });

  const { credential } = result.registrationInfo;
  db.transaction(() => {
    db.prepare(
      'INSERT INTO credentials (credential_id, user_id, public_key, counter, transports) VALUES (?,?,?,?,?)'
    ).run(
      credential.id,
      pending.userId,
      Buffer.from(credential.publicKey),
      credential.counter,
      JSON.stringify(credential.transports || [])
    );
    db.prepare('UPDATE users SET enrol_used = 1 WHERE id = ?').run(pending.userId);
  })();
  res.json({ verified: true });
});

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not signed in' });
  const user = db.prepare('SELECT id, name, role FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not signed in' });
  req.user = user;
  next();
};

app.post('/api/login/options', async (req, res) => {
  const userId = String(req.body.userId || '');
  const creds = db.prepare('SELECT credential_id, transports FROM credentials WHERE user_id = ?').all(userId);
  if (!creds.length) return res.status(403).json({ error: 'Authentication failed' });

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: creds.map((c) => ({
      id: c.credential_id,
      transports: JSON.parse(c.transports),
    })),
  });
  req.session.auth = { userId, challenge: options.challenge };
  res.json(options);
});

app.post('/api/login/verify', async (req, res) => {
  const pending = req.session.auth;
  delete req.session.auth;
  if (!pending) return res.status(400).json({ error: 'No login in progress' });

  const row = db
    .prepare('SELECT * FROM credentials WHERE credential_id = ? AND user_id = ?')
    .get(String(req.body.id), pending.userId);
  if (!row) return res.status(403).json({ error: 'Authentication failed' });

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: row.credential_id,
        publicKey: new Uint8Array(row.public_key),
        counter: row.counter,
        transports: JSON.parse(row.transports),
      },
    });
  } catch {
    return res.status(403).json({ error: 'Authentication failed' });
  }
  if (!result.verified) return res.status(403).json({ error: 'Authentication failed' });

  db.prepare('UPDATE credentials SET counter = ? WHERE credential_id = ?')
    .run(result.authenticationInfo.newCounter, row.credential_id);

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.userId = pending.userId;
    res.json({ verified: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => res.json(req.user));

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});


const deny = (res) => res.status(403).json({ error: 'Access denied' });

const requireRole = (role) => (req, res, next) =>
  req.user.role === role ? next() : deny(res);

const gradeRows = (studentId, lecturerId) => {
  const base = `SELECT c.id AS course_id, c.title, g.grade
                FROM grades g JOIN courses c ON c.id = g.course_id
                WHERE g.student_id = ?`;
  return lecturerId
    ? db.prepare(`${base} AND c.lecturer_id = ?`).all(studentId, lecturerId)
    : db.prepare(base).all(studentId);
};

app.get('/api/students/:id/grades', requireAuth, (req, res) => {
  const studentId = String(req.params.id);
  const { user } = req;
  if (user.role === 'student') {
    if (studentId !== user.id) return deny(res);
    return res.json({ studentId, grades: gradeRows(studentId) });
  }
  if (user.role === 'lecturer') {
    const rows = gradeRows(studentId, user.id);
    if (!rows.length) return deny(res);
    return res.json({ studentId, grades: rows });
  }
  deny(res);
});

app.get('/api/courses/:courseId/roster', requireAuth, requireRole('lecturer'), (req, res) => {
  const course = db
    .prepare('SELECT id FROM courses WHERE id = ? AND lecturer_id = ?')
    .get(String(req.params.courseId), req.user.id);
  if (!course) return deny(res);
  const roster = db.prepare(
    `SELECT u.id, u.name, g.grade
     FROM enrolments e
     JOIN users u ON u.id = e.student_id
     LEFT JOIN grades g ON g.course_id = e.course_id AND g.student_id = e.student_id
     WHERE e.course_id = ?`
  ).all(course.id);
  res.json({ courseId: course.id, roster });
});

app.put('/api/courses/:courseId/grades/:studentId', requireAuth, requireRole('lecturer'), (req, res) => {
  const course = db
    .prepare('SELECT id FROM courses WHERE id = ? AND lecturer_id = ?')
    .get(String(req.params.courseId), req.user.id);
  if (!course) return deny(res);

  const { grade } = req.body;
  if (!Number.isInteger(grade) || grade < 0 || grade > 100) {
    return res.status(400).json({ error: 'Grade must be a whole number from 0 to 100' });
  }
  const info = db
    .prepare('UPDATE grades SET grade = ? WHERE course_id = ? AND student_id = ?')
    .run(grade, course.id, String(req.params.studentId));
  if (info.changes === 0) return res.status(404).json({ error: 'Student not enrolled in this course' });
  res.json({ updated: true });
});

app.put('/api/users/:id/role', requireAuth, (req, res) => deny(res));

app.listen(3000, () => console.log('Running on http://localhost:3000'));
