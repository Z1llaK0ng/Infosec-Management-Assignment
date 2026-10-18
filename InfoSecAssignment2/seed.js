const crypto = require('crypto');
const db = require('./db');

const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');
const users = [
  ['S1', 'Ama Mensah', 'student'],
  ['S2', 'Kofi Boateng', 'student'],
  ['L1', 'Dr. Efua Owusu', 'lecturer'],
];

db.exec('DELETE FROM grades; DELETE FROM enrolments; DELETE FROM courses; DELETE FROM credentials; DELETE FROM users;');

const insertUser = db.prepare('INSERT INTO users (id,name,role,enrol_code_hash) VALUES (?,?,?,?)');
for (const [id, name, role] of users) {
  const code = crypto.randomBytes(6).toString('hex');
  insertUser.run(id, name, role, hash(code));
  console.log(`${id} (${role}) enrolment code: ${code}`);
}

db.prepare('INSERT INTO courses VALUES (?,?,?)').run('C1', 'Applied Security', 'L1');
db.prepare('INSERT INTO enrolments VALUES (?,?)').run('C1', 'S1');
db.prepare('INSERT INTO enrolments VALUES (?,?)').run('C1', 'S2');
db.prepare('INSERT INTO grades VALUES (?,?,?)').run('C1', 'S1', 78);
db.prepare('INSERT INTO grades VALUES (?,?,?)').run('C1', 'S2', 64);
