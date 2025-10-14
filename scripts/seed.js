import { open } from 'sqlite';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';

async function main() {
  const db = await open({ filename: './data.db', driver: sqlite3.Database });
  const email = 'demo@example.com';
  const phone = '9999999999';
  const passwordHash = await bcrypt.hash('password123', 10);
  try {
    await db.run('INSERT INTO users(email, phone, password_hash) VALUES (?, ?, ?)', [email, phone, passwordHash]);
    console.log('Seeded demo user:', email, phone);
  } catch (e) {
    console.log('User may already exist:', String(e).slice(0, 120));
  }
  await db.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
