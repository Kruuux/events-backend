import fs from 'node:fs/promises';
import path from 'node:path';
import pg from 'pg';

const { Pool } = pg;

const MIGRATIONS_DIR = path.join(import.meta.dirname, '..', 'migrations');

async function getMigrationFiles() {
  const files = await fs.readdir(MIGRATIONS_DIR);
  return files.filter((f) => f.endsWith('.sql')).sort();
}

async function getAppliedMigrations(pool: pg.Pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS migrations (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  const { rows } = await pool.query('SELECT name FROM migrations');
  return new Set(rows.map((r) => r.name as string));
}

export async function validateMigrations(pool: pg.Pool) {
  const applied = await getAppliedMigrations(pool);
  const files = await getMigrationFiles();
  const pending = files.filter((f) => !applied.has(f));

  if (pending.length > 0) {
    throw new Error(
      `pending migrations not applied: ${pending.join(', ')}. Run "npm run migrate" first.`,
    );
  }
}

async function runMigrations(pool: pg.Pool) {
  const applied = await getAppliedMigrations(pool);
  const files = await getMigrationFiles();
  const pending = files.filter((f) => !applied.has(f));

  if (pending.length === 0) {
    console.log('no pending migrations');
    return;
  }

  for (const file of pending) {
    const sql = await fs.readFile(path.join(MIGRATIONS_DIR, file), 'utf-8');
    await pool.query(sql);
    await pool.query('INSERT INTO migrations (name) VALUES ($1)', [file]);
    console.log(`migration applied: ${file}`);
  }
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(import.meta.filename);

if (isMain) {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  runMigrations(pool)
    .then(() => pool.end())
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
