import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';

const BASE_URL = process.env.BASE_URL ?? 'http://localhost:3000';
let pool: pg.Pool;

before(async () => {
  pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  await pool.query(
    'TRUNCATE events, places, cities, countries, organisations, sessions, humans CASCADE',
  );
});

after(async () => {
  await pool.end();
});

describe('POST /api/v1/join', () => {
  it('returns 201 for valid data', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'joinok',
        email: 'join-ok@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    assert.equal(res.status, 201);
  });

  it('returns 400 when body is empty', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as { code: string };
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 400 when nickname is too short', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'a',
        email: 'join-short-nick@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 400 when nickname is too long', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'a'.repeat(33),
        email: 'join-long-nick@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 400 when email is invalid', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'bademail',
        email: 'not-an-email',
        password: 'password123',
        role: 'member',
      }),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 400 when password is too short', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'shortpw',
        email: 'join-short-pw@test.com',
        password: 'short',
        role: 'member',
      }),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 400 when password is too long', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'longpw',
        email: 'join-long-pw@test.com',
        password: 'a'.repeat(129),
        role: 'member',
      }),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 400 when role is invalid', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'badrole',
        email: 'join-bad-role@test.com',
        password: 'password123',
        role: 'superadmin',
      }),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 409 when email is already taken', async () => {
    await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'dupemail1',
        email: 'join-dupe-email@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'dupemail2',
        email: 'join-dupe-email@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    assert.equal(res.status, 409);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'EMAIL_ALREADY_TAKEN_EXCEPTION');
  });

  it('returns 409 when nickname is already taken', async () => {
    await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'dupnick',
        email: 'join-dupe-nick1@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    const res = await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'dupnick',
        email: 'join-dupe-nick2@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    assert.equal(res.status, 409);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'NICKNAME_ALREADY_TAKEN_EXCEPTION');
  });
});

describe('POST /api/v1/enter', () => {
  it('returns 200 with accessToken and refreshToken for valid credentials', async () => {
    await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'enterok',
        email: 'enter-ok@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    const res = await fetch(`${BASE_URL}/api/v1/enter`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'enter-ok@test.com',
        password: 'password123',
      }),
    });

    assert.equal(res.status, 200);
    const body = (await res.json()) as Record<string, unknown>;
    assert.ok(body.accessToken);
    assert.ok(body.refreshToken);
  });

  it('returns 400 when body is empty', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/enter`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 400 when email is invalid', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/enter`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'not-an-email',
        password: 'password123',
      }),
    });

    assert.equal(res.status, 400);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'VALIDATION_EXCEPTION');
  });

  it('returns 401 when email does not exist', async () => {
    const res = await fetch(`${BASE_URL}/api/v1/enter`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'nonexistent@test.com',
        password: 'password123',
      }),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'INVALID_CREDENTIALS_EXCEPTION');
  });

  it('returns 401 when password is wrong', async () => {
    await fetch(`${BASE_URL}/api/v1/join`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        nickname: 'enterwrongpw',
        email: 'enter-wrong-pw@test.com',
        password: 'password123',
        role: 'member',
      }),
    });

    const res = await fetch(`${BASE_URL}/api/v1/enter`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'enter-wrong-pw@test.com',
        password: 'wrongpassword',
      }),
    });

    assert.equal(res.status, 401);
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.code, 'INVALID_CREDENTIALS_EXCEPTION');
  });
});
