const Database = require('better-sqlite3');
const db = new Database('portal.db');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('student','lecturer')),
  enrol_code_hash TEXT,
  enrol_used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS credentials (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT
);
CREATE TABLE IF NOT EXISTS courses (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  lecturer_id TEXT NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS enrolments (
  course_id TEXT NOT NULL REFERENCES courses(id),
  student_id TEXT NOT NULL REFERENCES users(id),
  PRIMARY KEY (course_id, student_id)
);
CREATE TABLE IF NOT EXISTS grades (
  course_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  grade INTEGER NOT NULL,
  PRIMARY KEY (course_id, student_id),
  FOREIGN KEY (course_id, student_id) REFERENCES enrolments(course_id, student_id)
);
`);

module.exports = db;
