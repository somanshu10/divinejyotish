import { open } from 'sqlite';
import sqlite3 from 'sqlite3';

async function main() {
  const db = await open({ filename: './data.db', driver: sqlite3.Database });
  await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        metadata TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      );
      CREATE INDEX IF NOT EXISTS idx_activities_user_created ON activities(user_id, created_at DESC);
  `);
  await db.close();
  console.log('Database initialized.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
