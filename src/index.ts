import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import * as v from 'valibot';
import { validateMigrations } from './migrate.js';

const { Pool } = pg;

function validateEnv() {
  const required = ['DATABASE_URL', 'JWT_SECRET', 'PORT'] as const;
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(
      `invalid configuration: missing env variables: ${missing.join(', ')}`,
    );
  }
  return {
    databaseUrl: process.env.DATABASE_URL!,
    jwtSecret: process.env.JWT_SECRET!,
    port: Number(process.env.PORT),
  };
}

const env = validateEnv();
const pool = new Pool({ connectionString: env.databaseUrl });
const JWT_SECRET = env.jwtSecret;
const PORT = env.port;

function validate<T extends v.GenericSchema>(
  schema: T,
  data: unknown,
  res: Response,
): v.InferOutput<T> | null {
  const result = v.safeParse(schema, data, {
    abortEarly: false,
    abortPipeEarly: false,
  });
  if (result.success) return result.output;

  const violations = result.issues.map((issue) => ({
    property: issue.path?.map((p) => p.key).join('.') ?? '',
    message: issue.message,
  }));

  res.status(400).json({ code: 'VALIDATION_EXCEPTION', violations });
  return null;
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function createSession(
  humanId: string,
  expiresAt: Date,
): Promise<string> {
  const refreshToken = jwt.sign({ sub: humanId, type: 'refresh' }, JWT_SECRET, {
    expiresIn: '1h',
  });
  await pool.query(
    'INSERT INTO sessions (id, human_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)',
    [crypto.randomUUID(), humanId, hashToken(refreshToken), expiresAt],
  );
  return refreshToken;
}

function authenticate(req: Request): jwt.JwtPayload | null {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET) as jwt.JwtPayload;
    if (payload.type === 'refresh') return null;
    return payload;
  } catch {
    return null;
  }
}

const UuidSchema = v.pipe(v.string(), v.uuid());

const IdParamSchema = v.object({
  id: UuidSchema,
});

const PaginationSchema = v.object({
  page: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '1'),
  limit: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '20'),
});

const app = express();
app.use(express.json());

// --- auth ---

const JoinSchema = v.object({
  nickname: v.pipe(v.string(), v.minLength(2), v.maxLength(32)),
  email: v.pipe(v.string(), v.email(), v.maxLength(254)),
  password: v.pipe(v.string(), v.minLength(8), v.maxLength(128)),
  role: v.picklist(['admin', 'member']),
});

app.post('/api/v1/join', async (req: Request, res: Response) => {
  const data = validate(JoinSchema, req.body, res);
  if (!data) return;

  const { nickname, email, password, role } = data;

  const emailCheck = await pool.query(
    'SELECT id FROM humans WHERE email = $1',
    [email],
  );
  if (emailCheck.rows.length > 0) {
    res.status(409).json({ code: 'EMAIL_ALREADY_TAKEN_EXCEPTION' });
    return;
  }

  const nicknameCheck = await pool.query(
    'SELECT id FROM humans WHERE nickname = $1',
    [nickname],
  );
  if (nicknameCheck.rows.length > 0) {
    res.status(409).json({ code: 'NICKNAME_ALREADY_TAKEN_EXCEPTION' });
    return;
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await new Promise<string>((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey.toString('hex'));
    });
  });

  await pool.query(
    'INSERT INTO humans (id, nickname, email, password_hash, salt, role) VALUES ($1, $2, $3, $4, $5, $6)',
    [crypto.randomUUID(), nickname, email, hash, salt, role],
  );

  res.status(201).end();
});

const EnterSchema = v.object({
  email: v.pipe(v.string(), v.email()),
  password: v.string(),
});

app.post('/api/v1/enter', async (req: Request, res: Response) => {
  const data = validate(EnterSchema, req.body, res);
  if (!data) return;

  const { email, password } = data;

  const humanResult = await pool.query(
    'SELECT id, nickname, email, password_hash, salt, role FROM humans WHERE email = $1',
    [email],
  );

  if (humanResult.rows.length === 0) {
    res.status(401).json({ code: 'INVALID_CREDENTIALS_EXCEPTION' });
    return;
  }

  const human = humanResult.rows[0]!;

  const hash = await new Promise<string>((resolve, reject) => {
    crypto.scrypt(password, human.salt as string, 64, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey.toString('hex'));
    });
  });

  if (hash !== human.password_hash) {
    res.status(401).json({ code: 'INVALID_CREDENTIALS_EXCEPTION' });
    return;
  }

  const accessToken = jwt.sign(
    {
      sub: human.id,
      role: human.role,
      nickname: human.nickname,
      email: human.email,
    },
    JWT_SECRET,
    { expiresIn: '15m' },
  );
  const refreshToken = await createSession(
    human.id as string,
    new Date(Date.now() + 60 * 60 * 1000),
  );

  res.status(200).json({ accessToken, refreshToken });
});

const RefreshSchema = v.object({
  refreshToken: v.string(),
});

app.post('/api/v1/refresh', async (req: Request, res: Response) => {
  const data = validate(RefreshSchema, req.body, res);
  if (!data) return;

  let payload: jwt.JwtPayload;
  try {
    payload = jwt.verify(data.refreshToken, JWT_SECRET) as jwt.JwtPayload;
  } catch {
    res.status(401).json({ code: 'INVALID_REFRESH_TOKEN_EXCEPTION' });
    return;
  }

  if (payload.type !== 'refresh') {
    res.status(401).json({ code: 'INVALID_REFRESH_TOKEN_EXCEPTION' });
    return;
  }

  const oldHash = hashToken(data.refreshToken);
  const session = await pool.query(
    'DELETE FROM sessions WHERE token_hash = $1 RETURNING human_id',
    [oldHash],
  );

  if (session.rows.length === 0) {
    res.status(401).json({ code: 'INVALID_REFRESH_TOKEN_EXCEPTION' });
    return;
  }

  const humanId = session.rows[0]!.human_id as string;

  const humanResult = await pool.query(
    'SELECT nickname, email, role FROM humans WHERE id = $1',
    [humanId],
  );
  const { nickname, email: humanEmail, role } = humanResult.rows[0]!;

  const accessToken = jwt.sign(
    { sub: humanId, role, nickname, email: humanEmail },
    JWT_SECRET,
    { expiresIn: '15m' },
  );
  const refreshToken = await createSession(
    humanId,
    new Date(Date.now() + 60 * 60 * 1000),
  );

  res.status(200).json({ accessToken, refreshToken });
});

const LogoutSchema = v.object({
  refreshToken: v.string(),
});

app.post('/api/v1/logout', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const data = validate(LogoutSchema, req.body, res);
  if (!data) return;

  const tokenHash = hashToken(data.refreshToken);
  const result = await pool.query(
    'DELETE FROM sessions WHERE token_hash = $1 AND human_id = $2',
    [tokenHash, payload.sub],
  );

  if (result.rowCount === 0) {
    res.status(404).json({ code: 'SESSION_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).end();
});

app.post('/api/v1/logout-all', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  await pool.query('DELETE FROM sessions WHERE human_id = $1', [payload.sub]);

  res.status(200).end();
});

// --- humans ---

const HumanSearchSchema = v.object({
  nickname: v.pipe(v.string(), v.minLength(2)),
  limit: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '10'),
});

app.get('/api/v1/humans', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const query = validate(HumanSearchSchema, req.query, res);
  if (!query) return;

  const limit = Math.min(50, Math.max(1, Number(query.limit)));

  const rows = await pool.query(
    `SELECT id, nickname FROM humans
     WHERE nickname ILIKE '%' || $1 || '%'
     ORDER BY nickname ASC LIMIT $2`,
    [query.nickname, limit],
  );

  res.status(200).json(rows.rows);
});

// --- organisations ---

const CreateOrganisationSchema = v.object({
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
});

app.post('/api/v1/organisations', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const data = validate(CreateOrganisationSchema, req.body, res);
  if (!data) return;

  const nameCheck = await pool.query(
    'SELECT id FROM organisations WHERE name = $1',
    [data.name],
  );
  if (nameCheck.rows.length > 0) {
    res.status(409).json({ code: 'ORGANISATION_NAME_ALREADY_TAKEN_EXCEPTION' });
    return;
  }

  const orgId = crypto.randomUUID();
  const row = await pool.query(
    `INSERT INTO organisations (id, human_id, name)
     VALUES ($1, $2, $3)
     RETURNING id, human_id AS "humanId", name, created_at AS "createdAt"`,
    [orgId, payload.sub, data.name],
  );

  res.status(201).json(row.rows[0]);
});

const OrganisationListSchema = v.object({
  page: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '1'),
  limit: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '20'),
  name: v.optional(v.string()),
  onlyFavourites: v.optional(v.string()),
});

app.get('/api/v1/organisations', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const query = validate(OrganisationListSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: unknown[] = [limit, offset, payload.sub];
  const countParams: unknown[] = [payload.sub];
  let paramIdx = 4;
  let countIdx = 2;

  if (query.name) {
    conditions.push(`org.name ILIKE '%' || $${paramIdx} || '%'`);
    params.push(query.name);
    countParams.push(query.name);
    paramIdx++;
    countIdx++;
  }
  if (query.onlyFavourites === 'true') {
    conditions.push('fo.human_id IS NOT NULL');
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const countConditions: string[] = [];
  let ci = 2;
  if (query.name) {
    countConditions.push(`org.name ILIKE '%' || $${ci} || '%'`);
    ci++;
  }
  if (query.onlyFavourites === 'true') {
    countConditions.push('fo.human_id IS NOT NULL');
  }
  const countWhere = countConditions.length > 0 ? `WHERE ${countConditions.join(' AND ')}` : '';

  const [countResult, rows] = await Promise.all([
    pool.query(
      `SELECT COUNT(*) FROM organisations org
       LEFT JOIN favourite_organisations fo ON fo.organisation_id = org.id AND fo.human_id = $1
       ${countWhere}`,
      countParams,
    ),
    pool.query(
      `SELECT org.id, org.human_id AS "humanId", org.name, org.created_at AS "createdAt",
              CASE WHEN fo.human_id IS NOT NULL THEN true ELSE false END AS "isFavourite"
       FROM organisations org
       LEFT JOIN favourite_organisations fo ON fo.organisation_id = org.id AND fo.human_id = $3
       ${where} ORDER BY org.name ASC LIMIT $1 OFFSET $2`,
      params,
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);

  res.status(200).json({ data: rows.rows, count: total });
});

app.get('/api/v1/organisations/:id', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    `SELECT id, human_id AS "humanId", name, created_at AS "createdAt"
     FROM organisations WHERE id = $1`,
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

const UpdateOrganisationSchema = v.object({
  id: UuidSchema,
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
});

app.put('/api/v1/organisations/:id', async (req: Request, res: Response) => {
  const data = validate(
    UpdateOrganisationSchema,
    { ...req.params, ...req.body },
    res,
  );
  if (!data) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const nameCheck = await pool.query(
    'SELECT id FROM organisations WHERE name = $1 AND id != $2',
    [data.name, data.id],
  );
  if (nameCheck.rows.length > 0) {
    res.status(409).json({ code: 'ORGANISATION_NAME_ALREADY_TAKEN_EXCEPTION' });
    return;
  }

  const row = await pool.query(
    `UPDATE organisations SET name = $1 WHERE id = $2
     RETURNING id, human_id AS "humanId", name, created_at AS "createdAt"`,
    [data.name, data.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.delete('/api/v1/organisations/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const row = await pool.query(
    'DELETE FROM organisations WHERE id = $1 RETURNING id',
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).end();
});

app.get(
  '/api/v1/organisations/:organisationId/events',
  async (req: Request, res: Response) => {
    const payload = authenticate(req);
    if (!payload) {
      res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
      return;
    }

    const organisationId = req.params.organisationId;
    const query = validate(PaginationSchema, req.query, res);
    if (!query) return;

    const page = Math.max(1, Number(query.page));
    const limit = Math.min(100, Math.max(1, Number(query.limit)));
    const offset = (page - 1) * limit;

    const [countResult, rows] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM events WHERE organisation_id = $1', [
        organisationId,
      ]),
      pool.query(
        `SELECT e.id, e.human_id AS "humanId", e.organisation_id AS "organisationId",
                e.place_id AS "placeId", e.title, e.description,
                p.latitude, p.longitude, p.name AS "placeName", p.address AS "placeAddress",
                e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
                o.name AS "organisationName"
         FROM events e
         JOIN places p ON p.id = e.place_id
         LEFT JOIN organisations o ON o.id = e.organisation_id
         WHERE e.organisation_id = $1
         ORDER BY CASE WHEN e.start_date >= CURRENT_DATE THEN 0 ELSE 1 END,
                  CASE WHEN e.start_date >= CURRENT_DATE THEN e.start_date END ASC,
                  CASE WHEN e.start_date < CURRENT_DATE THEN e.start_date END DESC
         LIMIT $2 OFFSET $3`,
        [organisationId, limit, offset],
      ),
    ]);

    const total = Number(countResult.rows[0]!.count);
    res.status(200).json({ data: rows.rows, count: total });
  },
);

app.get('/api/v1/places/:placeId/events', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const placeId = req.params.placeId;
  const query = validate(PaginationSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const [countResult, rows] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM events WHERE place_id = $1', [placeId]),
    pool.query(
      `SELECT e.id, e.human_id AS "humanId", e.organisation_id AS "organisationId",
                e.place_id AS "placeId", e.title, e.description,
                p.latitude, p.longitude, p.name AS "placeName", p.address AS "placeAddress",
                e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
                o.name AS "organisationName"
         FROM events e
         JOIN places p ON p.id = e.place_id
         LEFT JOIN organisations o ON o.id = e.organisation_id
         WHERE e.place_id = $1
         ORDER BY CASE WHEN e.start_date >= CURRENT_DATE THEN 0 ELSE 1 END,
                  CASE WHEN e.start_date >= CURRENT_DATE THEN e.start_date END ASC,
                  CASE WHEN e.start_date < CURRENT_DATE THEN e.start_date END DESC
         LIMIT $2 OFFSET $3`,
      [placeId, limit, offset],
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);
  res.status(200).json({ data: rows.rows, count: total });
});

// --- countries ---

const CreateCountrySchema = v.object({
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
});

const UpdateCountrySchema = v.object({
  id: UuidSchema,
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
});

app.post('/api/v1/countries', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const data = validate(CreateCountrySchema, req.body, res);
  if (!data) return;

  const nameCheck = await pool.query(
    'SELECT id FROM countries WHERE name = $1',
    [data.name],
  );
  if (nameCheck.rows.length > 0) {
    res.status(409).json({ code: 'COUNTRY_NAME_ALREADY_TAKEN_EXCEPTION' });
    return;
  }

  const id = crypto.randomUUID();
  const row = await pool.query(
    `INSERT INTO countries (id, name)
     VALUES ($1, $2)
     RETURNING id, name, created_at AS "createdAt", updated_at AS "updatedAt"`,
    [id, data.name],
  );

  res.status(201).json(row.rows[0]);
});

const CountryListSchema = v.object({
  page: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '1'),
  limit: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '20'),
  name: v.optional(v.string()),
});

app.get('/api/v1/countries', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const query = validate(CountryListSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const where = query.name ? `WHERE name ILIKE '%' || $3 || '%'` : '';
  const params = query.name ? [limit, offset, query.name] : [limit, offset];
  const countParams = query.name ? [query.name] : [];
  const countWhere = query.name ? `WHERE name ILIKE '%' || $1 || '%'` : '';

  const [countResult, rows] = await Promise.all([
    pool.query(`SELECT COUNT(*) FROM countries ${countWhere}`, countParams),
    pool.query(
      `SELECT id, name, created_at AS "createdAt", updated_at AS "updatedAt"
       FROM countries ${where} ORDER BY name ASC LIMIT $1 OFFSET $2`,
      params,
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);
  res.status(200).json({ data: rows.rows, count: total });
});

app.get('/api/v1/countries/:id', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    `SELECT id, name, created_at AS "createdAt", updated_at AS "updatedAt"
     FROM countries WHERE id = $1`,
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.put('/api/v1/countries/:id', async (req: Request, res: Response) => {
  const data = validate(
    UpdateCountrySchema,
    { ...req.params, ...req.body },
    res,
  );
  if (!data) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const nameCheck = await pool.query(
    'SELECT id FROM countries WHERE name = $1 AND id != $2',
    [data.name, data.id],
  );
  if (nameCheck.rows.length > 0) {
    res.status(409).json({ code: 'COUNTRY_NAME_ALREADY_TAKEN_EXCEPTION' });
    return;
  }

  const row = await pool.query(
    `UPDATE countries SET name = $1, updated_at = NOW() WHERE id = $2
     RETURNING id, name, created_at AS "createdAt", updated_at AS "updatedAt"`,
    [data.name, data.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.delete('/api/v1/countries/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  try {
    const row = await pool.query(
      'DELETE FROM countries WHERE id = $1 RETURNING id',
      [params.id],
    );

    if (row.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    res.status(200).end();
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      err.message.includes('violates foreign key constraint')
    ) {
      res.status(409).json({ code: 'COUNTRY_HAS_DEPENDENCIES_EXCEPTION' });
      return;
    }
    throw err;
  }
});

// --- cities ---

const CreateCitySchema = v.object({
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  countryId: UuidSchema,
});

const UpdateCitySchema = v.object({
  id: UuidSchema,
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  countryId: UuidSchema,
});

app.post('/api/v1/cities', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const data = validate(CreateCitySchema, req.body, res);
  if (!data) return;

  const countryCheck = await pool.query(
    'SELECT id FROM countries WHERE id = $1',
    [data.countryId],
  );
  if (countryCheck.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  const id = crypto.randomUUID();
  const row = await pool.query(
    `INSERT INTO cities (id, country_id, name)
     VALUES ($1, $2, $3)
     RETURNING id, country_id AS "countryId", name, created_at AS "createdAt", updated_at AS "updatedAt"`,
    [id, data.countryId, data.name],
  );

  res.status(201).json(row.rows[0]);
});

const CityListSchema = v.object({
  page: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '1'),
  limit: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '20'),
  name: v.optional(v.string()),
  countryId: v.optional(UuidSchema),
});

app.get('/api/v1/cities', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const query = validate(CityListSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: unknown[] = [limit, offset];
  const countParams: unknown[] = [];
  let paramIdx = 3;
  let countIdx = 1;

  if (query.name) {
    conditions.push(`c.name ILIKE '%' || $${paramIdx} || '%'`);
    params.push(query.name);
    countParams.push(query.name);
    paramIdx++;
    countIdx++;
  }
  if (query.countryId) {
    conditions.push(`c.country_id = $${paramIdx}`);
    params.push(query.countryId);
    countParams.push(query.countryId);
    paramIdx++;
    countIdx++;
  }

  const where =
    conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const countConditions: string[] = [];
  let ci = 1;
  if (query.name) {
    countConditions.push(`c.name ILIKE '%' || $${ci} || '%'`);
    ci++;
  }
  if (query.countryId) {
    countConditions.push(`c.country_id = $${ci}`);
    ci++;
  }
  const countWhere =
    countConditions.length > 0 ? `WHERE ${countConditions.join(' AND ')}` : '';

  const [countResult, rows] = await Promise.all([
    pool.query(`SELECT COUNT(*) FROM cities c ${countWhere}`, countParams),
    pool.query(
      `SELECT c.id, c.country_id AS "countryId", c.name, co.name AS "countryName",
              c.created_at AS "createdAt", c.updated_at AS "updatedAt"
       FROM cities c JOIN countries co ON co.id = c.country_id
       ${where} ORDER BY c.name ASC LIMIT $1 OFFSET $2`,
      params,
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);
  res.status(200).json({ data: rows.rows, count: total });
});

app.get('/api/v1/cities/:id', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    `SELECT c.id, c.country_id AS "countryId", c.name, co.name AS "countryName",
            c.created_at AS "createdAt", c.updated_at AS "updatedAt"
     FROM cities c JOIN countries co ON co.id = c.country_id
     WHERE c.id = $1`,
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.put('/api/v1/cities/:id', async (req: Request, res: Response) => {
  const data = validate(UpdateCitySchema, { ...req.params, ...req.body }, res);
  if (!data) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const countryCheck = await pool.query(
    'SELECT id FROM countries WHERE id = $1',
    [data.countryId],
  );
  if (countryCheck.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  const row = await pool.query(
    `UPDATE cities SET name = $1, country_id = $2, updated_at = NOW() WHERE id = $3
     RETURNING id, country_id AS "countryId", name, created_at AS "createdAt", updated_at AS "updatedAt"`,
    [data.name, data.countryId, data.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.delete('/api/v1/cities/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  try {
    const row = await pool.query(
      'DELETE FROM cities WHERE id = $1 RETURNING id',
      [params.id],
    );

    if (row.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    res.status(200).end();
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      err.message.includes('violates foreign key constraint')
    ) {
      res.status(409).json({ code: 'CITY_HAS_DEPENDENCIES_EXCEPTION' });
      return;
    }
    throw err;
  }
});

// --- places ---

const CreatePlaceSchema = v.object({
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  address: v.pipe(v.string(), v.minLength(1)),
  latitude: v.pipe(v.number(), v.minValue(-90), v.maxValue(90)),
  longitude: v.pipe(v.number(), v.minValue(-180), v.maxValue(180)),
  cityId: UuidSchema,
});

const UpdatePlaceSchema = v.object({
  id: UuidSchema,
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  address: v.pipe(v.string(), v.minLength(1)),
  latitude: v.pipe(v.number(), v.minValue(-90), v.maxValue(90)),
  longitude: v.pipe(v.number(), v.minValue(-180), v.maxValue(180)),
  cityId: UuidSchema,
});

app.post('/api/v1/places', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const data = validate(CreatePlaceSchema, req.body, res);
  if (!data) return;

  const cityCheck = await pool.query('SELECT id FROM cities WHERE id = $1', [
    data.cityId,
  ]);
  if (cityCheck.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  const id = crypto.randomUUID();
  const row = await pool.query(
    `INSERT INTO places (id, city_id, name, address, latitude, longitude)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, city_id AS "cityId", name, address, latitude, longitude, created_at AS "createdAt", updated_at AS "updatedAt"`,
    [id, data.cityId, data.name, data.address, data.latitude, data.longitude],
  );

  res.status(201).json(row.rows[0]);
});

const PlaceListSchema = v.object({
  page: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '1'),
  limit: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '20'),
  search: v.optional(v.string()),
  cityId: v.optional(UuidSchema),
  onlyFavourites: v.optional(v.string()),
});

app.get('/api/v1/places', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const query = validate(PlaceListSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: unknown[] = [limit, offset, payload.sub];
  const countParams: unknown[] = [payload.sub];
  let paramIdx = 4;
  let countIdx = 2;

  if (query.search) {
    conditions.push(
      `(p.name ILIKE '%' || $${paramIdx} || '%' OR p.address ILIKE '%' || $${paramIdx} || '%')`,
    );
    params.push(query.search);
    countParams.push(query.search);
    paramIdx++;
    countIdx++;
  }
  if (query.cityId) {
    conditions.push(`p.city_id = $${paramIdx}`);
    params.push(query.cityId);
    countParams.push(query.cityId);
    paramIdx++;
    countIdx++;
  }
  if (query.onlyFavourites === 'true') {
    conditions.push('fp.human_id IS NOT NULL');
  }

  const where =
    conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const countConditions: string[] = [];
  let ci = 2;
  if (query.search) {
    countConditions.push(
      `(p.name ILIKE '%' || $${ci} || '%' OR p.address ILIKE '%' || $${ci} || '%')`,
    );
    ci++;
  }
  if (query.cityId) {
    countConditions.push(`p.city_id = $${ci}`);
    ci++;
  }
  if (query.onlyFavourites === 'true') {
    countConditions.push('fp.human_id IS NOT NULL');
  }
  const countWhere =
    countConditions.length > 0 ? `WHERE ${countConditions.join(' AND ')}` : '';

  const [countResult, rows] = await Promise.all([
    pool.query(
      `SELECT COUNT(*) FROM places p
       LEFT JOIN favourite_places fp ON fp.place_id = p.id AND fp.human_id = $1
       ${countWhere}`,
      countParams,
    ),
    pool.query(
      `SELECT p.id, p.city_id AS "cityId", p.name, p.address, p.latitude, p.longitude,
              ci.name AS "cityName", co.name AS "countryName",
              p.created_at AS "createdAt", p.updated_at AS "updatedAt",
              CASE WHEN fp.human_id IS NOT NULL THEN true ELSE false END AS "isFavourite"
       FROM places p
       JOIN cities ci ON ci.id = p.city_id
       JOIN countries co ON co.id = ci.country_id
       LEFT JOIN favourite_places fp ON fp.place_id = p.id AND fp.human_id = $3
       ${where} ORDER BY p.name ASC LIMIT $1 OFFSET $2`,
      params,
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);
  res.status(200).json({ data: rows.rows, count: total });
});

app.get('/api/v1/places/:id', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    `SELECT p.id, p.city_id AS "cityId", p.name, p.address, p.latitude, p.longitude,
            ci.name AS "cityName", co.name AS "countryName",
            p.created_at AS "createdAt", p.updated_at AS "updatedAt"
     FROM places p
     JOIN cities ci ON ci.id = p.city_id
     JOIN countries co ON co.id = ci.country_id
     WHERE p.id = $1`,
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.put('/api/v1/places/:id', async (req: Request, res: Response) => {
  const data = validate(UpdatePlaceSchema, { ...req.params, ...req.body }, res);
  if (!data) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const cityCheck = await pool.query('SELECT id FROM cities WHERE id = $1', [
    data.cityId,
  ]);
  if (cityCheck.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  const row = await pool.query(
    `UPDATE places SET name = $1, address = $2, latitude = $3, longitude = $4, city_id = $5, updated_at = NOW()
     WHERE id = $6
     RETURNING id, city_id AS "cityId", name, address, latitude, longitude, created_at AS "createdAt", updated_at AS "updatedAt"`,
    [
      data.name,
      data.address,
      data.latitude,
      data.longitude,
      data.cityId,
      data.id,
    ],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.delete('/api/v1/places/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  try {
    const row = await pool.query(
      'DELETE FROM places WHERE id = $1 RETURNING id',
      [params.id],
    );

    if (row.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    res.status(200).end();
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      err.message.includes('violates foreign key constraint')
    ) {
      res.status(409).json({ code: 'PLACE_HAS_EVENTS_EXCEPTION' });
      return;
    }
    throw err;
  }
});

// --- favourites ---

const FavouriteOrganisationSchema = v.object({
  organisationId: UuidSchema,
});

app.post('/api/v1/favourite-organisations', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const data = validate(FavouriteOrganisationSchema, req.body, res);
  if (!data) return;

  await pool.query(
    'INSERT INTO favourite_organisations (human_id, organisation_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
    [payload.sub, data.organisationId],
  );

  res.status(200).end();
});

const FavouriteOrganisationParamSchema = v.object({
  organisationId: UuidSchema,
});

app.delete('/api/v1/favourite-organisations/:organisationId', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const params = validate(FavouriteOrganisationParamSchema, req.params, res);
  if (!params) return;

  await pool.query(
    'DELETE FROM favourite_organisations WHERE human_id = $1 AND organisation_id = $2',
    [payload.sub, params.organisationId],
  );

  res.status(200).end();
});

const FavouritePlaceSchema = v.object({
  placeId: UuidSchema,
});

app.post('/api/v1/favourite-places', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const data = validate(FavouritePlaceSchema, req.body, res);
  if (!data) return;

  await pool.query(
    'INSERT INTO favourite_places (human_id, place_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
    [payload.sub, data.placeId],
  );

  res.status(200).end();
});

const FavouritePlaceParamSchema = v.object({
  placeId: UuidSchema,
});

app.delete('/api/v1/favourite-places/:placeId', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const params = validate(FavouritePlaceParamSchema, req.params, res);
  if (!params) return;

  await pool.query(
    'DELETE FROM favourite_places WHERE human_id = $1 AND place_id = $2',
    [payload.sub, params.placeId],
  );

  res.status(200).end();
});

// --- events ---

const CreateEventSchema = v.object({
  title: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  description: v.string(),
  placeId: UuidSchema,
  startDate: v.pipe(v.string(), v.isoTimestamp()),
  endDate: v.pipe(v.string(), v.isoTimestamp()),
  organisationId: v.optional(UuidSchema),
});

app.post('/api/v1/events', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const data = validate(CreateEventSchema, req.body, res);
  if (!data) return;

  const placeCheck = await pool.query('SELECT id FROM places WHERE id = $1', [
    data.placeId,
  ]);
  if (placeCheck.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  if (data.organisationId != null) {
    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [data.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }
  }

  const eventId = crypto.randomUUID();
  const row = await pool.query(
    `INSERT INTO events (id, human_id, organisation_id, place_id, title, description, start_date, end_date)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, human_id AS "humanId", organisation_id AS "organisationId",
               place_id AS "placeId", title, description,
               start_date AS "startDate", end_date AS "endDate", created_at AS "createdAt"`,
    [
      eventId,
      payload.sub,
      data.organisationId ?? null,
      data.placeId,
      data.title,
      data.description,
      data.startDate,
      data.endDate,
    ],
  );

  res.status(201).json(row.rows[0]);
});

const EventListSchema = v.object({
  page: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '1'),
  limit: v.optional(v.pipe(v.string(), v.regex(/^\d+$/)), '20'),
  search: v.optional(v.string()),
  cityId: v.optional(UuidSchema),
});

app.get('/api/v1/events', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const query = validate(EventListSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const conditions: string[] = ['e.start_date >= CURRENT_DATE'];
  const params: unknown[] = [limit, offset];
  const countParams: unknown[] = [];
  let paramIdx = 3;
  let countIdx = 1;

  if (query.search) {
    conditions.push(
      `(e.title ILIKE '%' || $${paramIdx} || '%' OR p.name ILIKE '%' || $${paramIdx} || '%' OR o.name ILIKE '%' || $${paramIdx} || '%')`,
    );
    params.push(query.search);
    countParams.push(query.search);
    paramIdx++;
    countIdx++;
  }
  if (query.cityId) {
    conditions.push(`p.city_id = $${paramIdx}`);
    params.push(query.cityId);
    countParams.push(query.cityId);
    paramIdx++;
    countIdx++;
  }

  const where = conditions.join(' AND ');
  const countConditions: string[] = ['e.start_date >= CURRENT_DATE'];
  let ci = 1;
  if (query.search) {
    countConditions.push(
      `(e.title ILIKE '%' || $${ci} || '%' OR p.name ILIKE '%' || $${ci} || '%' OR o.name ILIKE '%' || $${ci} || '%')`,
    );
    ci++;
  }
  if (query.cityId) {
    countConditions.push(`p.city_id = $${ci}`);
    ci++;
  }
  const countWhere = countConditions.join(' AND ');

  const [countResult, rows] = await Promise.all([
    pool.query(
      `SELECT COUNT(*) FROM events e
       JOIN places p ON p.id = e.place_id
       LEFT JOIN organisations o ON o.id = e.organisation_id
       WHERE ${countWhere}`,
      countParams,
    ),
    pool.query(
      `SELECT e.id, e.human_id AS "humanId", e.organisation_id AS "organisationId",
              e.place_id AS "placeId", e.title, e.description,
              p.latitude, p.longitude, p.name AS "placeName", p.address AS "placeAddress",
              e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
              o.name AS "organisationName"
       FROM events e
       JOIN places p ON p.id = e.place_id
       LEFT JOIN organisations o ON o.id = e.organisation_id
       WHERE ${where}
       ORDER BY e.start_date ASC LIMIT $1 OFFSET $2`,
      params,
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);

  res.status(200).json({ data: rows.rows, count: total });
});

const CoordPipe = (min: number, max: number) =>
  v.pipe(
    v.string(),
    v.transform(Number),
    v.number(),
    v.minValue(min),
    v.maxValue(max),
  );

const EventsAreaSchema = v.object({
  minLat: CoordPipe(-90, 90),
  maxLat: CoordPipe(-90, 90),
  minLng: CoordPipe(-180, 180),
  maxLng: CoordPipe(-180, 180),
});

app.get('/api/v1/events/area', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const query = validate(EventsAreaSchema, req.query, res);
  if (!query) return;

  const latKm = (query.maxLat - query.minLat) * 111;
  const midLatRad = ((query.minLat + query.maxLat) / 2) * (Math.PI / 180);
  const lngKm = (query.maxLng - query.minLng) * 111 * Math.cos(midLatRad);

  if (latKm > 10 || lngKm > 10) {
    res.status(400).json({ code: 'AREA_TOO_LARGE_EXCEPTION' });
    return;
  }

  const rows = await pool.query(
    `SELECT e.id, e.human_id AS "humanId", e.organisation_id AS "organisationId",
            e.place_id AS "placeId", e.title, e.description,
            p.latitude, p.longitude, p.name AS "placeName", p.address AS "placeAddress",
            e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
            o.name AS "organisationName"
     FROM events e
     JOIN places p ON p.id = e.place_id
     LEFT JOIN organisations o ON o.id = e.organisation_id
     WHERE e.start_date >= CURRENT_DATE
       AND p.latitude >= $1 AND p.latitude <= $2
       AND p.longitude >= $3 AND p.longitude <= $4
     ORDER BY e.start_date ASC`,
    [query.minLat, query.maxLat, query.minLng, query.maxLng],
  );

  res.status(200).json({ data: rows.rows });
});

app.get('/api/v1/events/:id', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    `SELECT e.id, e.human_id AS "humanId", e.organisation_id AS "organisationId",
            e.place_id AS "placeId", e.title, e.description,
            p.latitude, p.longitude, p.name AS "placeName", p.address AS "placeAddress",
            e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
            o.name AS "organisationName"
     FROM events e
     JOIN places p ON p.id = e.place_id
     LEFT JOIN organisations o ON o.id = e.organisation_id
     WHERE e.id = $1`,
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

const UpdateEventSchema = v.object({
  id: UuidSchema,
  title: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  description: v.string(),
  placeId: UuidSchema,
  startDate: v.pipe(v.string(), v.isoTimestamp()),
  endDate: v.pipe(v.string(), v.isoTimestamp()),
  organisationId: v.optional(v.nullable(UuidSchema)),
});

app.put('/api/v1/events/:id', async (req: Request, res: Response) => {
  const data = validate(UpdateEventSchema, { ...req.params, ...req.body }, res);
  if (!data) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const existing = await pool.query('SELECT id FROM events WHERE id = $1', [
    data.id,
  ]);
  if (existing.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  const placeCheck = await pool.query('SELECT id FROM places WHERE id = $1', [
    data.placeId,
  ]);
  if (placeCheck.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  if (data.organisationId != null) {
    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [data.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }
  }

  const row = await pool.query(
    `UPDATE events SET title = $1, description = $2, place_id = $3, start_date = $4, end_date = $5, organisation_id = $6
     WHERE id = $7
     RETURNING id, human_id AS "humanId", organisation_id AS "organisationId",
               place_id AS "placeId", title, description,
               start_date AS "startDate", end_date AS "endDate", created_at AS "createdAt"`,
    [
      data.title,
      data.description,
      data.placeId,
      data.startDate,
      data.endDate,
      data.organisationId ?? null,
      data.id,
    ],
  );

  res.status(200).json(row.rows[0]);
});

app.delete('/api/v1/events/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
    return;
  }

  const row = await pool.query(
    'DELETE FROM events WHERE id = $1 RETURNING id',
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).end();
});

// --- pages ---

const PAGE_STYLE = `*{margin:0;padding:0;box-sizing:border-box}body{background:#fff;color:#000;font-family:monospace;font-size:16px}.c{max-width:1000px;margin:0 auto;padding:24px 16px}a{color:#000}nav{margin:8px 0 16px}hr{border:none;border-top:1px solid #000;margin:16px 0}input,select{border:1px solid #000;padding:6px;margin:4px 0 12px;width:100%;font-family:monospace;font-size:16px}button{border:1px solid #000;background:#fff;color:#000;padding:6px 16px;font-family:monospace;font-size:16px;cursor:pointer}#err{font-weight:bold;margin-top:12px}.dropdown{border:1px solid #000;max-height:150px;overflow-y:auto;display:none}.dropdown div{padding:4px 6px;cursor:pointer}.dropdown div:hover{background:#000;color:#fff}.bc{margin:8px 0;font-size:14px}.searchRow{display:flex;align-items:center;gap:12px;margin-bottom:12px}.searchRow input{flex:1;margin-bottom:0}#cityPicker{position:relative}#cityPicker input{width:180px;margin:0}#cityPicker .dropdown{position:absolute;right:0;width:180px;background:#fff;z-index:10}`;
const PAGE_HEAD = `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${PAGE_STYLE}</style>`;
const NAV_SCRIPT = `<script>
(function(){const t=localStorage.getItem('accessToken');if(!t)return;
try{const p=JSON.parse(atob(t.split('.')[1]));
if(p.role==='admin'){const s=document.getElementById('adminNav');if(s)s.style.display='inline'}}catch{};
const ph=window.location.pathname;let ah='/';
if(ph==='/organisations-list'||ph.startsWith('/view/organisation/')||ph.startsWith('/edit/organisation/'))ah='/organisations-list';
else if(ph==='/places-list'||ph.startsWith('/view/place/'))ah='/places-list';
else if(ph==='/countries-list')ah='/countries-list';
else if(ph==='/cities-list')ah='/cities-list';
else if(ph==='/profile')ah='/profile';
document.querySelectorAll('nav a').forEach(function(a){if(a.getAttribute('href')===ah)a.style.fontWeight='bold'});
})();
(function(){
var t=localStorage.getItem('accessToken');if(!t)return;
var cityBtn=document.getElementById('cityBtn');
var cityInputWrap=document.getElementById('cityInputWrap');
var cityInput=document.getElementById('cityInput');
var cityDrop=document.getElementById('cityDrop');
if(!cityBtn||!cityInput)return;
function updateBtn(){
  var id=localStorage.getItem('selectedCityId');
  var name=localStorage.getItem('selectedCityName');
  if(id&&name){cityBtn.textContent=name+' [x]'}else{cityBtn.textContent='All cities'}
}
updateBtn();
function showDrop(cities){
  cityDrop.innerHTML='';
  var all=document.createElement('div');
  all.textContent='All cities';
  all.onmousedown=function(e){e.preventDefault()};
  all.onclick=function(){
    localStorage.removeItem('selectedCityId');
    localStorage.removeItem('selectedCityName');
    updateBtn();
    cityInputWrap.style.display='none';cityBtn.style.display='';
    cityInput.value='';cityDrop.style.display='none';
    if(window.onCityChange)window.onCityChange();
  };
  cityDrop.appendChild(all);
  for(var i=0;i<cities.length;i++){
    var d=document.createElement('div');
    d.textContent=cities[i].name;
    d.dataset.id=cities[i].id;
    d.dataset.name=cities[i].name;
    d.onmousedown=function(e){e.preventDefault()};
    d.onclick=function(){
      localStorage.setItem('selectedCityId',this.dataset.id);
      localStorage.setItem('selectedCityName',this.dataset.name);
      updateBtn();
      cityInputWrap.style.display='none';cityBtn.style.display='';
      cityInput.value='';cityDrop.style.display='none';
      if(window.onCityChange)window.onCityChange();
    };
    cityDrop.appendChild(d);
  }
  cityDrop.style.display='block';
}
function fetchCities(name){
  var url='/api/v1/cities?limit=20';
  if(name)url+='&name='+encodeURIComponent(name);
  fetch(url,{headers:{'Authorization':'Bearer '+t}}).then(function(r){return r.json()}).then(function(j){showDrop(j.data||[])});
}
cityBtn.onclick=function(e){
  e.preventDefault();
  var id=localStorage.getItem('selectedCityId');
  if(id&&this.textContent.indexOf('[x]')!==-1){
    var rect=this.getBoundingClientRect();
    var btnW=rect.width;
    var xStart=rect.right-20;
    if(e.clientX>=xStart){
      localStorage.removeItem('selectedCityId');
      localStorage.removeItem('selectedCityName');
      updateBtn();
      if(window.onCityChange)window.onCityChange();
      return;
    }
  }
  this.style.display='none';
  cityInputWrap.style.display='';
  cityInput.focus();
  fetchCities();
};
var cityDebounce;
cityInput.oninput=function(){
  clearTimeout(cityDebounce);
  var v=this.value.trim();
  cityDebounce=setTimeout(function(){
    if(v.length>=2){fetchCities(v)}else{fetchCities()}
  },300);
};
cityInput.onblur=function(){
  setTimeout(function(){cityDrop.style.display='none';cityInputWrap.style.display='none';cityBtn.style.display=''},150);
};
})();
</script>`;
const APP_NAV = `<nav style="display:flex;align-items:center;justify-content:space-between"><span>[<a href="/">Events</a>] [<a href="/organisations-list">Organisations</a>] [<a href="/places-list">Places</a>] <span id="adminNav" style="display:none">[<a href="/countries-list">Countries</a>] [<a href="/cities-list">Cities</a>] </span>[<a href="/profile">Profile</a>]</span><span id="cityPicker"><button id="cityBtn">All cities</button><span id="cityInputWrap" style="display:none"><input type="text" id="cityInput" placeholder="Search city..." autocomplete="off"><div class="dropdown" id="cityDrop"></div></span></span></nav>${NAV_SCRIPT}`;

const ORG_SEARCH_HTML = `Organisation (optional)<br><input type="text" id="orgSearch" placeholder="Search by name..." autocomplete="off"><input type="hidden" name="organisationId" id="orgId"><div class="dropdown" id="orgDrop"></div>`;
const ORG_SEARCH_SCRIPT = `
let debounce;
document.getElementById('orgSearch').oninput=function(){
  clearTimeout(debounce);
  const v=this.value;
  const drop=document.getElementById('orgDrop');
  if(v.length<2){drop.style.display='none';document.getElementById('orgId').value='';return}
  debounce=setTimeout(async()=>{
    const r=await fetch('/api/v1/organisations?name='+encodeURIComponent(v)+'&limit=10',{headers:{'Authorization':'Bearer '+localStorage.getItem('accessToken')}});
    if(!r.ok)return;
    const j=await r.json();
    drop.innerHTML='';
    if(j.data.length===0){drop.style.display='none';return}
    for(const o of j.data){
      const d=document.createElement('div');
      d.textContent=o.name;
      d.onclick=()=>{document.getElementById('orgSearch').value=o.name;document.getElementById('orgId').value=o.id;drop.style.display='none'};
      drop.appendChild(d);
    }
    drop.style.display='block';
  },300);
};
document.addEventListener('click',e=>{if(!e.target.closest('#orgSearch,#orgDrop'))document.getElementById('orgDrop').style.display='none'});`;

const PLACE_SEARCH_HTML = `Place<br><input type="text" id="placeSearch" placeholder="Search by name or address..." autocomplete="off" required><input type="hidden" name="placeId" id="placeId" required><div class="dropdown" id="placeDrop"></div>`;
const PLACE_SEARCH_SCRIPT = `
let placeDebounce;
document.getElementById('placeSearch').oninput=function(){
  clearTimeout(placeDebounce);
  const v=this.value;
  const drop=document.getElementById('placeDrop');
  if(v.length<2){drop.style.display='none';document.getElementById('placeId').value='';return}
  placeDebounce=setTimeout(async()=>{
    const r=await fetch('/api/v1/places?search='+encodeURIComponent(v)+'&limit=10',{headers:{'Authorization':'Bearer '+localStorage.getItem('accessToken')}});
    if(!r.ok)return;
    const j=await r.json();
    drop.innerHTML='';
    if(j.data.length===0){drop.style.display='none';return}
    for(const p of j.data){
      const d=document.createElement('div');
      d.textContent=p.name+' - '+p.address;
      d.onclick=()=>{document.getElementById('placeSearch').value=p.name+' - '+p.address;document.getElementById('placeId').value=p.id;drop.style.display='none'};
      drop.appendChild(d);
    }
    drop.style.display='block';
  },300);
};
document.addEventListener('click',e=>{if(!e.target.closest('#placeSearch,#placeDrop'))document.getElementById('placeDrop').style.display='none'});`;

app.get('/', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}<style>#end{display:none}.leaflet-popup-content-wrapper,.leaflet-popup-tip{background:#fff;color:#000;border-radius:0;box-shadow:none;border:1px solid #000}.leaflet-popup-content{font-family:monospace;font-size:14px}.leaflet-container a{color:#000}.leaflet-control-zoom a{background:#fff;color:#000;border:1px solid #000;border-radius:0}.leaflet-control-attribution{font-family:monospace;font-size:11px}</style>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
</head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<div id="createForm" style="display:none">
<b>Create event</b><br>
Title<br><input type="text" id="evTitle" required><br>
Description<br><input type="text" id="evDescription" required><br>
${PLACE_SEARCH_HTML}<br>
Start<br><input type="datetime-local" id="evStart" required><br>
End<br><input type="datetime-local" id="evEnd" required><br>
${ORG_SEARCH_HTML}<br>
<button id="createBtn">Create</button>
<p id="err"></p>
<hr>
</div>
<p class="bc">Events /</p>
<input type="text" id="searchInput" placeholder="Search events..." style="margin-bottom:12px">
<p id="toggle"><b>list</b> | <a href="#" id="toMap">map</a></p>
<div id="listView">
<div id="list"></div>
<p id="loading">Loading...</p>
<p id="end">---</p>
</div>
<div id="mapView" style="display:none">
<p id="mapMsg" style="margin:8px 0"></p>
<div id="map" style="width:100%;height:600px;border:1px solid #000"></div>
</div>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
const t=localStorage.getItem('accessToken');
let me={};
try{me=JSON.parse(atob(t.split('.')[1]))}catch{}

// --- create form (admin only) ---
if(me.role==='admin'){
  document.getElementById('createForm').style.display='block';
  ${PLACE_SEARCH_SCRIPT}
  ${ORG_SEARCH_SCRIPT}
  document.getElementById('createBtn').onclick=async()=>{
    const title=document.getElementById('evTitle').value.trim();
    const description=document.getElementById('evDescription').value.trim();
    const placeId=document.getElementById('placeId').value;
    const startDate=document.getElementById('evStart').value;
    const endDate=document.getElementById('evEnd').value;
    const organisationId=document.getElementById('orgId').value;
    if(!title||!description||!placeId||!startDate||!endDate){document.getElementById('err').textContent='Please fill all required fields';return}
    const body={title,description,placeId,startDate:new Date(startDate).toISOString(),endDate:new Date(endDate).toISOString()};
    if(organisationId)body.organisationId=organisationId;
    const r=await fetch('/api/v1/events',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify(body)});
    if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
    document.getElementById('err').textContent='';
    document.getElementById('evTitle').value='';
    document.getElementById('evDescription').value='';
    document.getElementById('placeId').value='';
    document.getElementById('placeSearch').value='';
    document.getElementById('evStart').value='';
    document.getElementById('evEnd').value='';
    document.getElementById('orgId').value='';
    document.getElementById('orgSearch').value='';
    page=1;done=false;lastDateLabel='';
    document.getElementById('list').innerHTML='';
    load();
  };
}

// --- list view ---
let page=1;const limit=20;let loading=false;let done=false;
let lastDateLabel='';let searchTerm='';
function dateLabel(ds){
  const dt=new Date(ds);
  const now=new Date();
  const today=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  const tmrw=new Date(today);tmrw.setDate(tmrw.getDate()+1);
  const dd=new Date(dt.getFullYear(),dt.getMonth(),dt.getDate());
  if(dd.getTime()===today.getTime())return 'Today';
  if(dd.getTime()===tmrw.getTime())return 'Tomorrow';
  return dt.getDate()+' '+dt.toLocaleString('en',{month:'long'})+' '+dt.getFullYear();
}
let searchDebounce;
document.getElementById('searchInput').oninput=function(){
  clearTimeout(searchDebounce);
  const v=this.value.trim();
  searchDebounce=setTimeout(()=>{
    if(v.length>=2){searchTerm=v}else{searchTerm=''}
    page=1;done=false;lastDateLabel='';
    document.getElementById('list').innerHTML='';
    document.getElementById('end').style.display='none';
    load();
  },300);
};
async function load(){
  if(loading||done)return;
  loading=true;
  document.getElementById('loading').style.display='block';
  let url='/api/v1/events?page='+page+'&limit='+limit;
  if(searchTerm)url+='&search='+encodeURIComponent(searchTerm);
  var sc=localStorage.getItem('selectedCityId');if(sc)url+='&cityId='+sc;
  const r=await fetch(url,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){loading=false;document.getElementById('loading').style.display='none';return}
  const j=await r.json();
  const list=document.getElementById('list');
  for(const ev of j.data){
    const lbl=dateLabel(ev.startDate);
    if(lbl!==lastDateLabel){
      lastDateLabel=lbl;
      const h=document.createElement('h2');
      h.style.margin='24px 0 12px';
      h.textContent=lbl;
      list.appendChild(h);
    }
    const dv=document.createElement('div');
    let evHtml='<a href="/view/event/'+ev.id+'"><b>'+esc(ev.title)+'</b></a><br>'
      +esc(ev.description)+'<br>';
    if(ev.placeName)evHtml+='<small>Place: <a href="/view/place/'+ev.placeId+'">'+esc(ev.placeName)+'</a></small><br>';
    if(ev.organisationName)evHtml+='<small>Organisation: <a href="/view/organisation/'+ev.organisationId+'">'+esc(ev.organisationName)+'</a></small><br>';
    if(me.role==='admin')evHtml+='<a href="/edit/event/'+ev.id+'">[edit]</a> <a href="#" class="delEv" data-id="'+ev.id+'">[delete]</a><br>';
    evHtml+='<hr>';
    dv.innerHTML=evHtml;
    list.appendChild(dv);
  }
  list.querySelectorAll('.delEv').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      if(!confirm('Delete this event?'))return;
      const r2=await fetch('/api/v1/events/'+a.dataset.id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!r2.ok){return}
      a.closest('div').remove();
    };
  });
  if(page*limit>=j.count){done=true;document.getElementById('end').style.display='block'}
  else{page++}
  loading=false;
  document.getElementById('loading').style.display=done?'none':'block';
}
window.addEventListener('scroll',()=>{
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-200)load();
});
window.onCityChange=function(){page=1;done=false;lastDateLabel='';document.getElementById('list').innerHTML='';document.getElementById('end').style.display='none';load()};
load();

// --- map view ---
let map=null;
let markers=[];

function initMap(){
  if(map)return;
  map=L.map('map',{attributionControl:false}).setView([51.110655,17.032817],15);
  L.control.attribution({prefix:false}).addTo(map);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
    attribution:'&copy; OpenStreetMap'
  }).addTo(map);
  map.on('moveend',loadArea);
  loadArea();
}

async function loadArea(){
  const b=map.getBounds();
  const minLat=b.getSouth(),maxLat=b.getNorth(),minLng=b.getWest(),maxLng=b.getEast();
  const latKm=(maxLat-minLat)*111;
  const lngKm=(maxLng-minLng)*111*Math.cos(((minLat+maxLat)/2)*Math.PI/180);
  const msg=document.getElementById('mapMsg');

  markers.forEach(m=>map.removeLayer(m));
  markers=[];

  if(latKm>10||lngKm>10){
    msg.textContent='Zoom in to see events (max 10\\u00d710 km area)';
    return;
  }
  msg.textContent='';

  const r=await fetch('/api/v1/events/area?minLat='+minLat+'&maxLat='+maxLat+'&minLng='+minLng+'&maxLng='+maxLng,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok)return;
  const j=await r.json();
  for(const ev of j.data){
    let popup='<div style="font-family:monospace;font-size:14px">'
      +'<b><a href="/view/event/'+ev.id+'">'+esc(ev.title)+'</a></b><br>'
      +esc(ev.description)+'<br>';
    if(ev.organisationName)popup+='<small>Organisation: <a href="/view/organisation/'+ev.organisationId+'">'+esc(ev.organisationName)+'</a></small><br>';
    popup+='<small>'+new Date(ev.startDate).toLocaleString()+' - '+new Date(ev.endDate).toLocaleString()+'</small></div>';
    const m=L.marker([ev.latitude,ev.longitude]).addTo(map).bindPopup(popup);
    markers.push(m);
  }
}

// --- toggle ---
document.getElementById('toMap').onclick=function(e){
  e.preventDefault();
  document.getElementById('listView').style.display='none';
  document.getElementById('mapView').style.display='block';
  document.getElementById('toggle').innerHTML='<a href="#" id="toList">list</a> | <b>map</b>';
  document.getElementById('toList').onclick=switchToList;
  initMap();
  setTimeout(()=>map.invalidateSize(),0);
};
function switchToList(e){
  e.preventDefault();
  document.getElementById('listView').style.display='block';
  document.getElementById('mapView').style.display='none';
  document.getElementById('toggle').innerHTML='<b>list</b> | <a href="#" id="toMap2">map</a>';
  document.getElementById('toMap2').onclick=function(e2){
    e2.preventDefault();
    document.getElementById('listView').style.display='none';
    document.getElementById('mapView').style.display='block';
    document.getElementById('toggle').innerHTML='<a href="#" id="toList">list</a> | <b>map</b>';
    document.getElementById('toList').onclick=switchToList;
    setTimeout(()=>map.invalidateSize(),0);
  };
}
</script>
</body></html>`);
});

app.get('/organisations-list', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}<style>#end{display:none}</style></head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<div id="createForm" style="display:none">
<b>Create organisation</b><br>
<input type="text" id="orgName" placeholder="Organisation name" required>
<button id="createBtn">Create</button>
<p id="err"></p>
<hr>
</div>
<p class="bc">Organisations /</p>
<div class="searchRow"><input type="text" id="searchInput" placeholder="Search organisations...">
<a href="#" id="favLink">[Show favourites]</a></div>
<div id="list"></div>
<p id="loading">Loading...</p>
<p id="end">---</p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const t=localStorage.getItem('accessToken');
let me={};
try{me=JSON.parse(atob(t.split('.')[1]))}catch{}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

if(me.role==='admin'){
  document.getElementById('createForm').style.display='block';
  document.getElementById('createBtn').onclick=async()=>{
    const name=document.getElementById('orgName').value.trim();
    if(!name)return;
    const r=await fetch('/api/v1/organisations',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({name})});
    if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
    document.getElementById('orgName').value='';
    document.getElementById('err').textContent='';
    page=1;done=false;
    document.getElementById('list').innerHTML='';
    load();
  };
}

let page=1;const limit=20;let loading=false;let done=false;
let searchTerm='';let onlyFavourites=false;
let searchDebounce;
document.getElementById('searchInput').oninput=function(){
  clearTimeout(searchDebounce);
  const v=this.value.trim();
  searchDebounce=setTimeout(()=>{
    if(v.length>=2){searchTerm=v}else{searchTerm=''}
    page=1;done=false;
    document.getElementById('list').innerHTML='';
    document.getElementById('end').style.display='none';
    load();
  },300);
};
document.getElementById('favLink').onclick=function(e){
  e.preventDefault();
  onlyFavourites=!onlyFavourites;
  this.textContent=onlyFavourites?'[Show all]':'[Show favourites]';
  page=1;done=false;
  document.getElementById('list').innerHTML='';
  document.getElementById('end').style.display='none';
  load();
};
async function load(){
  if(loading||done)return;
  loading=true;
  document.getElementById('loading').style.display='block';
  let url='/api/v1/organisations?page='+page+'&limit='+limit;
  if(searchTerm)url+='&name='+encodeURIComponent(searchTerm);
  if(onlyFavourites)url+='&onlyFavourites=true';
  const r=await fetch(url,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){loading=false;document.getElementById('loading').style.display='none';return}
  const j=await r.json();
  const list=document.getElementById('list');
  for(const o of j.data){
    const dv=document.createElement('div');
    let oHtml='<a href="/view/organisation/'+o.id+'"><b>'+esc(o.name)+'</b></a>';
    if(me.role==='admin')oHtml+=' <a href="/edit/organisation/'+o.id+'">[edit]</a> <a href="#" class="delOrg" data-id="'+o.id+'">[delete]</a>';
    oHtml+=' <a href="#" class="favOrg" style="float:right" data-id="'+o.id+'" data-fav="'+o.isFavourite+'">'+(o.isFavourite?'[Remove from favourites]':'[Add to favourites]')+'</a>';
    oHtml+='<hr>';
    dv.innerHTML=oHtml;
    list.appendChild(dv);
  }
  list.querySelectorAll('.delOrg').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      if(!confirm('Delete this organisation?'))return;
      const r2=await fetch('/api/v1/organisations/'+a.dataset.id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!r2.ok){const j2=await r2.json();document.getElementById('err').textContent=j2.code||JSON.stringify(j2);return}
      document.getElementById('err').textContent='';
      a.closest('div').remove();
    };
  });
  list.querySelectorAll('.favOrg').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      const isFav=a.dataset.fav==='true';
      if(isFav){
        await fetch('/api/v1/favourite-organisations/'+a.dataset.id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
        a.dataset.fav='false';a.textContent='[Add to favourites]';
      }else{
        await fetch('/api/v1/favourite-organisations',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({organisationId:a.dataset.id})});
        a.dataset.fav='true';a.textContent='[Remove from favourites]';
      }
    };
  });
  if(page*limit>=j.count){done=true;document.getElementById('end').style.display='block'}
  else{page++}
  loading=false;
  document.getElementById('loading').style.display=done?'none':'block';
}
window.addEventListener('scroll',()=>{
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-200)load();
});
load();
</script>
</body></html>`);
});

app.get('/view/event/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc" id="bc"><a href="/">Events</a> /</p>
<div id="detail"></div>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const id=window.location.pathname.split('/').pop();
const t=localStorage.getItem('accessToken');
let me={};
try{me=JSON.parse(atob(t.split('.')[1]))}catch{}
(async()=>{
  const r=await fetch('/api/v1/events/'+id,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const ev=await r.json();
  document.getElementById('bc').innerHTML='<a href="/">Events</a> / '+esc(ev.title);
  let html='<p>Description: '+esc(ev.description)+'</p>'
    +'<p>Place: <a href="/view/place/'+ev.placeId+'">'+esc(ev.placeName)+'</a> - '+esc(ev.placeAddress)+'</p>'
    +'<p>Start: '+new Date(ev.startDate).toLocaleString()+'</p>'
    +'<p>End: '+new Date(ev.endDate).toLocaleString()+'</p>';
  if(ev.organisationId)html+='<p>Organisation: <a href="/view/organisation/'+ev.organisationId+'">'+esc(ev.organisationName||ev.organisationId)+'</a></p>';
  const canEdit=me.role==='admin';
  if(canEdit){
    html+='<br><a href="/edit/event/'+ev.id+'">[edit]</a>';
    html+=' <a href="#" id="deleteBtn">[delete]</a>';
  }
  document.getElementById('detail').innerHTML=html;
  if(canEdit){
    document.getElementById('deleteBtn').onclick=async function(e){
      e.preventDefault();
      if(!confirm('Delete this event?'))return;
      const dr=await fetch('/api/v1/events/'+id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!dr.ok){const dj=await dr.json();document.getElementById('err').textContent=dj.code||JSON.stringify(dj);return}
      window.location.href='/';
    };
  }
})();
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
</script>
</body></html>`);
});

app.get('/view/organisation/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}<style>#end{display:none}</style></head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc" id="bc"><a href="/organisations-list">Organisations</a> /</p>
<div id="detail"></div>
<p id="err"></p>
<div id="eventsSection" style="display:none">
<h2 id="eventsTitle" style="margin:24px 0 12px">Events</h2>
<div id="list"></div>
<p id="loading">Loading...</p>
<p id="end">---</p>
</div>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const id=window.location.pathname.split('/').pop();
const t=localStorage.getItem('accessToken');
let me={};
try{me=JSON.parse(atob(t.split('.')[1]))}catch{}
(async()=>{
  const r=await fetch('/api/v1/organisations/'+id,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const o=await r.json();
  document.getElementById('bc').innerHTML='<a href="/organisations-list">Organisations</a> / '+esc(o.name);
  document.getElementById('eventsTitle').textContent='Events of '+o.name;
  let html='';
  if(me.role==='admin'){
    html+='<a href="/edit/organisation/'+o.id+'">[edit]</a>';
    html+=' <a href="#" id="deleteBtn">[delete]</a>';
  }
  document.getElementById('detail').innerHTML=html;
  if(me.role==='admin'){
    document.getElementById('deleteBtn').onclick=async function(e){
      e.preventDefault();
      if(!confirm('Delete this organisation?'))return;
      const dr=await fetch('/api/v1/organisations/'+id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!dr.ok){const dj=await dr.json();document.getElementById('err').textContent=dj.code||JSON.stringify(dj);return}
      window.location.href='/organisations-list';
    };
  }
  document.getElementById('eventsSection').style.display='block';
  loadEvents();
})();
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function dateLabel(ds){
  const d=new Date(ds);
  const now=new Date();
  const today=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  const tmrw=new Date(today);tmrw.setDate(tmrw.getDate()+1);
  const t2=new Date(d.getFullYear(),d.getMonth(),d.getDate());
  if(t2.getTime()===today.getTime())return 'Today';
  if(t2.getTime()===tmrw.getTime())return 'Tomorrow';
  return d.getDate()+' '+d.toLocaleString('en',{month:'long'})+' '+d.getFullYear();
}
let evPage=1;const evLimit=20;let evLoading=false;let evDone=false;let lastDateLabel='';
async function loadEvents(){
  if(evLoading||evDone)return;
  evLoading=true;
  document.getElementById('loading').style.display='block';
  const r=await fetch('/api/v1/organisations/'+id+'/events?page='+evPage+'&limit='+evLimit,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){evLoading=false;document.getElementById('loading').style.display='none';return}
  const j=await r.json();
  const list=document.getElementById('list');
  for(const ev of j.data){
    const lbl=dateLabel(ev.startDate);
    if(lbl!==lastDateLabel){
      lastDateLabel=lbl;
      const h=document.createElement('h3');
      h.style.margin='24px 0 12px';
      h.textContent=lbl;
      list.appendChild(h);
    }
    const d=document.createElement('div');
    let evHtml='<a href="/view/event/'+ev.id+'"><b>'+esc(ev.title)+'</b></a><br>'
      +esc(ev.description)+'<br><hr>';
    d.innerHTML=evHtml;
    list.appendChild(d);
  }
  if(evPage*evLimit>=j.count){evDone=true;document.getElementById('end').style.display='block'}
  else{evPage++}
  evLoading=false;
  document.getElementById('loading').style.display=evDone?'none':'block';
}
window.addEventListener('scroll',()=>{
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-200)loadEvents();
});
</script>
</body></html>`);
});

app.get('/view/place/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}<style>#end{display:none}</style></head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc" id="bc"><a href="/places-list">Places</a> /</p>
<div id="detail"></div>
<p id="err"></p>
<div id="eventsSection" style="display:none">
<h2 id="eventsTitle" style="margin:24px 0 12px">Events</h2>
<div id="list"></div>
<p id="loading">Loading...</p>
<p id="end">---</p>
</div>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const t=localStorage.getItem('accessToken');
const id=window.location.pathname.split('/').pop();
(async()=>{
  const r=await fetch('/api/v1/places/'+id,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const p=await r.json();
  document.getElementById('bc').innerHTML='<a href="/places-list">Places</a> / '+esc(p.name);
  document.getElementById('eventsTitle').textContent='Events in '+p.name;
  let html='<p>Address: '+esc(p.countryName)+', '+esc(p.cityName)+', '+esc(p.address)+'</p>'
    +'<p>Coordinates: '+p.latitude+', '+p.longitude+'</p>';
  document.getElementById('detail').innerHTML=html;
  document.getElementById('eventsSection').style.display='block';
  loadEvents();
})();
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function dateLabel(ds){
  const d=new Date(ds);
  const now=new Date();
  const today=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  const tmrw=new Date(today);tmrw.setDate(tmrw.getDate()+1);
  const t2=new Date(d.getFullYear(),d.getMonth(),d.getDate());
  if(t2.getTime()===today.getTime())return 'Today';
  if(t2.getTime()===tmrw.getTime())return 'Tomorrow';
  return d.getDate()+' '+d.toLocaleString('en',{month:'long'})+' '+d.getFullYear();
}
let evPage=1;const evLimit=20;let evLoading=false;let evDone=false;let lastDateLabel='';
async function loadEvents(){
  if(evLoading||evDone)return;
  evLoading=true;
  document.getElementById('loading').style.display='block';
  const r=await fetch('/api/v1/places/'+id+'/events?page='+evPage+'&limit='+evLimit,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){evLoading=false;document.getElementById('loading').style.display='none';return}
  const j=await r.json();
  const list=document.getElementById('list');
  for(const ev of j.data){
    const lbl=dateLabel(ev.startDate);
    if(lbl!==lastDateLabel){
      lastDateLabel=lbl;
      const h=document.createElement('h3');
      h.style.margin='24px 0 12px';
      h.textContent=lbl;
      list.appendChild(h);
    }
    const d=document.createElement('div');
    let evHtml='<a href="/view/event/'+ev.id+'"><b>'+esc(ev.title)+'</b></a><br>'
      +esc(ev.description)+'<br>';
    if(ev.organisationName)evHtml+='<small>Organisation: <a href="/view/organisation/'+ev.organisationId+'">'+esc(ev.organisationName)+'</a></small><br>';
    evHtml+='<hr>';
    d.innerHTML=evHtml;
    list.appendChild(d);
  }
  if(evPage*evLimit>=j.count){evDone=true;document.getElementById('end').style.display='block'}
  else{evPage++}
  evLoading=false;
  document.getElementById('loading').style.display=evDone?'none':'block';
}
window.addEventListener('scroll',()=>{
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-200)loadEvents();
});
</script>
</body></html>`);
});

app.get('/edit/event/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc" id="bc"><a href="/">Events</a> /</p>
<form id="f">
Title<br><input type="text" name="title" required><br>
Description<br><input type="text" name="description" required><br>
${PLACE_SEARCH_HTML}<br>
Start<br><input type="datetime-local" name="startDate" required><br>
End<br><input type="datetime-local" name="endDate" required><br>
${ORG_SEARCH_HTML}<br>
<button type="submit">Update</button>
</form>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
try{const p=JSON.parse(atob(localStorage.getItem('accessToken').split('.')[1]));if(p.role!=='admin')window.location.href='/'}catch{window.location.href='/login'}
const eventId=window.location.pathname.split('/').pop();
${PLACE_SEARCH_SCRIPT}
${ORG_SEARCH_SCRIPT}
(async()=>{
  const _t=localStorage.getItem('accessToken');
  const r=await fetch('/api/v1/events/'+eventId,{headers:{'Authorization':'Bearer '+_t}});
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const ev=await r.json();
  function _esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
  document.getElementById('bc').innerHTML='<a href="/">Events</a> / <a href="/view/event/'+eventId+'">'+_esc(ev.title)+'</a> / Edit';
  const f=document.getElementById('f');
  f.title.value=ev.title;
  f.description.value=ev.description;
  f.startDate.value=ev.startDate.slice(0,16);
  f.endDate.value=ev.endDate.slice(0,16);
  if(ev.placeId){
    document.getElementById('placeId').value=ev.placeId;
    document.getElementById('placeSearch').value=ev.placeName+' - '+ev.placeAddress;
  }
  if(ev.organisationId){
    document.getElementById('orgId').value=ev.organisationId;
    const or=await fetch('/api/v1/organisations/'+ev.organisationId,{headers:{'Authorization':'Bearer '+_t}});
    if(or.ok){const oj=await or.json();document.getElementById('orgSearch').value=oj.name}
  }
})();
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const fd=Object.fromEntries(new FormData(e.target));
  if(!fd.placeId){document.getElementById('err').textContent='Please select a place';return}
  const body={title:fd.title,description:fd.description,placeId:fd.placeId,startDate:new Date(fd.startDate).toISOString(),endDate:new Date(fd.endDate).toISOString()};
  if(fd.organisationId)body.organisationId=fd.organisationId;
  else body.organisationId=null;
  const r=await fetch('/api/v1/events/'+eventId,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('accessToken')},body:JSON.stringify(body)});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  window.location.href='/view/event/'+eventId;
};
</script>
</body></html>`);
});

app.get('/edit/organisation/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc" id="bc"><a href="/organisations-list">Organisations</a> /</p>
<form id="f">
Name<br><input type="text" name="name" minlength="1" maxlength="256" required><br><br>
<button type="submit">Update</button>
</form>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
try{const p=JSON.parse(atob(localStorage.getItem('accessToken').split('.')[1]));if(p.role!=='admin')window.location.href='/'}catch{window.location.href='/login'}
const orgId=window.location.pathname.split('/').pop();
(async()=>{
  const r=await fetch('/api/v1/organisations/'+orgId,{headers:{'Authorization':'Bearer '+localStorage.getItem('accessToken')}});
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const o=await r.json();
  function _esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
  document.getElementById('bc').innerHTML='<a href="/organisations-list">Organisations</a> / <a href="/view/organisation/'+orgId+'">'+_esc(o.name)+'</a> / Edit';
  document.getElementById('f').name.value=o.name;
})();
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const fd=Object.fromEntries(new FormData(e.target));
  const r=await fetch('/api/v1/organisations/'+orgId,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('accessToken')},body:JSON.stringify({name:fd.name})});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  window.location.href='/view/organisation/'+orgId;
};
</script>
</body></html>`);
});

// --- admin pages: countries, cities, places ---

app.get('/countries-list', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc">Countries /</p>
<div id="createForm">
<b>Add country</b><br>
<input type="text" id="countryName" placeholder="Country name" required>
<button id="createBtn">Create</button>
</div>
<br>
<div id="editForm" style="display:none">
<b>Edit country</b><br>
<input type="text" id="editName" placeholder="Country name" required>
<button id="saveBtn">Save</button> <button id="cancelBtn">Cancel</button>
</div>
<hr>
<div id="list"></div>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
try{const p=JSON.parse(atob(localStorage.getItem('accessToken').split('.')[1]));if(p.role!=='admin')window.location.href='/'}catch{window.location.href='/login'}
const t=localStorage.getItem('accessToken');
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
let editId=null;

document.getElementById('createBtn').onclick=async()=>{
  const name=document.getElementById('countryName').value.trim();
  if(!name)return;
  const r=await fetch('/api/v1/countries',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({name})});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  document.getElementById('countryName').value='';
  document.getElementById('err').textContent='';
  loadList();
};

document.getElementById('saveBtn').onclick=async()=>{
  const name=document.getElementById('editName').value.trim();
  if(!name||!editId)return;
  const r=await fetch('/api/v1/countries/'+editId,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({name})});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  document.getElementById('editForm').style.display='none';
  document.getElementById('createForm').style.display='block';
  editId=null;
  document.getElementById('err').textContent='';
  loadList();
};

document.getElementById('cancelBtn').onclick=()=>{
  document.getElementById('editForm').style.display='none';
  document.getElementById('createForm').style.display='block';
  editId=null;
};

async function loadList(){
  const r=await fetch('/api/v1/countries?limit=100',{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok)return;
  const j=await r.json();
  const list=document.getElementById('list');
  list.innerHTML='';
  for(const c of j.data){
    const d=document.createElement('div');
    d.innerHTML=esc(c.name)+' <a href="#" class="edit" data-id="'+c.id+'" data-name="'+esc(c.name)+'">[edit]</a> <a href="#" class="del" data-id="'+c.id+'">[delete]</a><hr>';
    list.appendChild(d);
  }
  list.querySelectorAll('.edit').forEach(a=>{
    a.onclick=e=>{
      e.preventDefault();
      editId=a.dataset.id;
      document.getElementById('editName').value=a.dataset.name;
      document.getElementById('editForm').style.display='block';
      document.getElementById('createForm').style.display='none';
    };
  });
  list.querySelectorAll('.del').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      if(!confirm('Delete this country?'))return;
      const r=await fetch('/api/v1/countries/'+a.dataset.id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
      document.getElementById('err').textContent='';
      loadList();
    };
  });
}
loadList();
</script>
</body></html>`);
});

app.get('/cities-list', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc">Cities /</p>
<div id="createForm">
<b>Add city</b><br>
Name<br><input type="text" id="cityName" placeholder="City name" required><br>
Country<br><select id="countrySelect"><option value="">-- select --</option></select><br><br>
<button id="createBtn">Create</button>
</div>
<br>
<div id="editForm" style="display:none">
<b>Edit city</b><br>
Name<br><input type="text" id="editName" placeholder="City name" required><br>
Country<br><select id="editCountrySelect"><option value="">-- select --</option></select><br><br>
<button id="saveBtn">Save</button> <button id="cancelBtn">Cancel</button>
</div>
<hr>
Filter by country: <select id="filterCountry"><option value="">All</option></select>
<hr>
<div id="list"></div>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
try{const p=JSON.parse(atob(localStorage.getItem('accessToken').split('.')[1]));if(p.role!=='admin')window.location.href='/'}catch{window.location.href='/login'}
const t=localStorage.getItem('accessToken');
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
let editId=null;
let countries=[];

async function loadCountries(){
  const r=await fetch('/api/v1/countries?limit=100',{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok)return;
  const j=await r.json();
  countries=j.data;
  for(const sel of [document.getElementById('countrySelect'),document.getElementById('editCountrySelect'),document.getElementById('filterCountry')]){
    const val=sel.value;
    const first=sel.options[0];
    sel.innerHTML='';
    sel.appendChild(first);
    for(const c of countries){
      const o=document.createElement('option');
      o.value=c.id;o.textContent=c.name;
      sel.appendChild(o);
    }
    sel.value=val;
  }
}

document.getElementById('filterCountry').onchange=()=>loadList();

document.getElementById('createBtn').onclick=async()=>{
  const name=document.getElementById('cityName').value.trim();
  const countryId=document.getElementById('countrySelect').value;
  if(!name||!countryId)return;
  const r=await fetch('/api/v1/cities',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({name,countryId})});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  document.getElementById('cityName').value='';
  document.getElementById('err').textContent='';
  loadList();
};

document.getElementById('saveBtn').onclick=async()=>{
  const name=document.getElementById('editName').value.trim();
  const countryId=document.getElementById('editCountrySelect').value;
  if(!name||!countryId||!editId)return;
  const r=await fetch('/api/v1/cities/'+editId,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({name,countryId})});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  document.getElementById('editForm').style.display='none';
  document.getElementById('createForm').style.display='block';
  editId=null;
  document.getElementById('err').textContent='';
  loadList();
};

document.getElementById('cancelBtn').onclick=()=>{
  document.getElementById('editForm').style.display='none';
  document.getElementById('createForm').style.display='block';
  editId=null;
};

async function loadList(){
  const countryId=document.getElementById('filterCountry').value;
  let url='/api/v1/cities?limit=100';
  if(countryId)url+='&countryId='+countryId;
  const r=await fetch(url,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok)return;
  const j=await r.json();
  const list=document.getElementById('list');
  list.innerHTML='';
  for(const c of j.data){
    const d=document.createElement('div');
    d.innerHTML=esc(c.name)+' <small>('+esc(c.countryName)+')</small> <a href="#" class="edit" data-id="'+c.id+'" data-name="'+esc(c.name)+'" data-country="'+c.countryId+'">[edit]</a> <a href="#" class="del" data-id="'+c.id+'">[delete]</a><hr>';
    list.appendChild(d);
  }
  list.querySelectorAll('.edit').forEach(a=>{
    a.onclick=e=>{
      e.preventDefault();
      editId=a.dataset.id;
      document.getElementById('editName').value=a.dataset.name;
      document.getElementById('editCountrySelect').value=a.dataset.country;
      document.getElementById('editForm').style.display='block';
      document.getElementById('createForm').style.display='none';
    };
  });
  list.querySelectorAll('.del').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      if(!confirm('Delete this city?'))return;
      const r=await fetch('/api/v1/cities/'+a.dataset.id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
      document.getElementById('err').textContent='';
      loadList();
    };
  });
}
loadCountries().then(()=>loadList());
</script>
</body></html>`);
});

app.get('/places-list', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}<style>#end{display:none}</style></head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<div id="createForm" style="display:none">
<b>Add place</b><br>
Name<br><input type="text" id="placeName" placeholder="Place name" required><br>
Address<br><input type="text" id="placeAddress" placeholder="Address" required><br>
Latitude<br><input type="number" id="placeLat" step="any" min="-90" max="90" required><br>
Longitude<br><input type="number" id="placeLng" step="any" min="-180" max="180" required><br>
City<br><select id="citySelect"><option value="">-- select --</option></select><br><br>
<button id="createBtn">Create</button>
</div>
<div id="editForm" style="display:none">
<b>Edit place</b><br>
Name<br><input type="text" id="editName" placeholder="Place name" required><br>
Address<br><input type="text" id="editAddress" placeholder="Address" required><br>
Latitude<br><input type="number" id="editLat" step="any" min="-90" max="90" required><br>
Longitude<br><input type="number" id="editLng" step="any" min="-180" max="180" required><br>
City<br><select id="editCitySelect"><option value="">-- select --</option></select><br><br>
<button id="saveBtn">Save</button> <button id="cancelBtn">Cancel</button>
</div>
<p id="err"></p>
<hr>
<p class="bc">Places /</p>
<div class="searchRow"><input type="text" id="searchInput" placeholder="Search places...">
<a href="#" id="favLink">[Show favourites]</a></div>
<div id="list"></div>
<p id="loading">Loading...</p>
<p id="end">---</p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const t=localStorage.getItem('accessToken');
let me={};
try{me=JSON.parse(atob(t.split('.')[1]))}catch{}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
let editId=null;

if(me.role==='admin'){
  document.getElementById('createForm').style.display='block';

  async function loadCities(){
    const r=await fetch('/api/v1/cities?limit=100',{headers:{'Authorization':'Bearer '+t}});
    if(!r.ok)return;
    const j=await r.json();
    for(const sel of [document.getElementById('citySelect'),document.getElementById('editCitySelect')]){
      const val=sel.value;
      const first=sel.options[0];
      sel.innerHTML='';
      sel.appendChild(first);
      for(const c of j.data){
        const o=document.createElement('option');
        o.value=c.id;o.textContent=c.name+' ('+c.countryName+')';
        sel.appendChild(o);
      }
      sel.value=val;
    }
  }
  loadCities();

  document.getElementById('createBtn').onclick=async()=>{
    const name=document.getElementById('placeName').value.trim();
    const address=document.getElementById('placeAddress').value.trim();
    const latitude=Number(document.getElementById('placeLat').value);
    const longitude=Number(document.getElementById('placeLng').value);
    const cityId=document.getElementById('citySelect').value;
    if(!name||!address||!cityId)return;
    const r=await fetch('/api/v1/places',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({name,address,latitude,longitude,cityId})});
    if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
    document.getElementById('placeName').value='';
    document.getElementById('placeAddress').value='';
    document.getElementById('placeLat').value='';
    document.getElementById('placeLng').value='';
    document.getElementById('err').textContent='';
    page=1;done=false;
    document.getElementById('list').innerHTML='';
    document.getElementById('end').style.display='none';
    load();
  };

  document.getElementById('saveBtn').onclick=async()=>{
    const name=document.getElementById('editName').value.trim();
    const address=document.getElementById('editAddress').value.trim();
    const latitude=Number(document.getElementById('editLat').value);
    const longitude=Number(document.getElementById('editLng').value);
    const cityId=document.getElementById('editCitySelect').value;
    if(!name||!address||!cityId||!editId)return;
    const r=await fetch('/api/v1/places/'+editId,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({name,address,latitude,longitude,cityId})});
    if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
    document.getElementById('editForm').style.display='none';
    document.getElementById('createForm').style.display='block';
    editId=null;
    document.getElementById('err').textContent='';
    page=1;done=false;
    document.getElementById('list').innerHTML='';
    document.getElementById('end').style.display='none';
    load();
  };

  document.getElementById('cancelBtn').onclick=()=>{
    document.getElementById('editForm').style.display='none';
    document.getElementById('createForm').style.display='block';
    editId=null;
  };
}

let page=1;const limit=20;let loading=false;let done=false;
let searchTerm='';let onlyFavourites=false;
let searchDebounce;
document.getElementById('searchInput').oninput=function(){
  clearTimeout(searchDebounce);
  const v=this.value.trim();
  searchDebounce=setTimeout(()=>{
    if(v.length>=2){searchTerm=v}else{searchTerm=''}
    page=1;done=false;
    document.getElementById('list').innerHTML='';
    document.getElementById('end').style.display='none';
    load();
  },300);
};
document.getElementById('favLink').onclick=function(e){
  e.preventDefault();
  onlyFavourites=!onlyFavourites;
  this.textContent=onlyFavourites?'[Show all]':'[Show favourites]';
  page=1;done=false;
  document.getElementById('list').innerHTML='';
  document.getElementById('end').style.display='none';
  load();
};
async function load(){
  if(loading||done)return;
  loading=true;
  document.getElementById('loading').style.display='block';
  let url='/api/v1/places?page='+page+'&limit='+limit;
  if(searchTerm)url+='&search='+encodeURIComponent(searchTerm);
  if(onlyFavourites)url+='&onlyFavourites=true';
  var sc=localStorage.getItem('selectedCityId');if(sc)url+='&cityId='+sc;
  const r=await fetch(url,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){loading=false;document.getElementById('loading').style.display='none';return}
  const j=await r.json();
  const list=document.getElementById('list');
  for(const p of j.data){
    const d=document.createElement('div');
    let pHtml='<a href="/view/place/'+p.id+'"><b>'+esc(p.name)+'</b></a><br>'+esc(p.address)+' <small>('+esc(p.cityName)+', '+esc(p.countryName)+')</small><br>'
      +'<small>Lat: '+p.latitude+', Lng: '+p.longitude+'</small>';
    if(me.role==='admin'){
      pHtml+=' <a href="#" class="edit" data-id="'+p.id+'" data-name="'+esc(p.name)+'" data-address="'+esc(p.address)+'" data-lat="'+p.latitude+'" data-lng="'+p.longitude+'" data-city="'+p.cityId+'">[edit]</a>'
        +' <a href="#" class="del" data-id="'+p.id+'">[delete]</a>';
    }
    pHtml+=' <a href="#" class="favPlace" style="float:right" data-id="'+p.id+'" data-fav="'+p.isFavourite+'">'+(p.isFavourite?'[Remove from favourites]':'[Add to favourites]')+'</a>';
    pHtml+='<hr>';
    d.innerHTML=pHtml;
    list.appendChild(d);
  }
  list.querySelectorAll('.edit').forEach(a=>{
    a.onclick=e=>{
      e.preventDefault();
      editId=a.dataset.id;
      document.getElementById('editName').value=a.dataset.name;
      document.getElementById('editAddress').value=a.dataset.address;
      document.getElementById('editLat').value=a.dataset.lat;
      document.getElementById('editLng').value=a.dataset.lng;
      document.getElementById('editCitySelect').value=a.dataset.city;
      document.getElementById('editForm').style.display='block';
      document.getElementById('createForm').style.display='none';
    };
  });
  list.querySelectorAll('.del').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      if(!confirm('Delete this place?'))return;
      const r=await fetch('/api/v1/places/'+a.dataset.id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
      document.getElementById('err').textContent='';
      a.closest('div').remove();
    };
  });
  list.querySelectorAll('.favPlace').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      const isFav=a.dataset.fav==='true';
      if(isFav){
        await fetch('/api/v1/favourite-places/'+a.dataset.id,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
        a.dataset.fav='false';a.textContent='[Add to favourites]';
      }else{
        await fetch('/api/v1/favourite-places',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({placeId:a.dataset.id})});
        a.dataset.fav='true';a.textContent='[Remove from favourites]';
      }
    };
  });
  if(page*limit>=j.count){done=true;document.getElementById('end').style.display='block'}
  else{page++}
  loading=false;
  document.getElementById('loading').style.display=done?'none':'block';
}
window.addEventListener('scroll',()=>{
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-200)load();
});
window.onCityChange=function(){page=1;done=false;document.getElementById('list').innerHTML='';document.getElementById('end').style.display='none';load()};
load();
</script>
</body></html>`);
});

app.get('/profile', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Events</h1>
${APP_NAV}
<hr>
<p class="bc">Profile /</p>
<p>Nickname: <b id="nick"></b></p>
<p>Email: <b id="email"></b> <small>(visible only to you)</small></p>
<br>
<button id="logout">Log out</button> <button id="logoutAll">Log out from all devices</button>
<p id="err"></p>
</div>
<script>
const t=localStorage.getItem('accessToken');
const rt=localStorage.getItem('refreshToken');
if(!t){window.location.href='/login'}
else{try{const p=JSON.parse(atob(t.split('.')[1]));document.getElementById('nick').textContent=p.nickname;document.getElementById('email').textContent=p.email}catch{window.location.href='/login'}}
function clearAndRedirect(){localStorage.removeItem('accessToken');localStorage.removeItem('refreshToken');window.location.href='/login'}
document.getElementById('logout').onclick=async()=>{
  if(rt){await fetch('/api/v1/logout',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({refreshToken:rt})})}
  clearAndRedirect();
};
document.getElementById('logoutAll').onclick=async()=>{
  await fetch('/api/v1/logout-all',{method:'POST',headers:{'Authorization':'Bearer '+t}});
  clearAndRedirect();
};
</script>
</body></html>`);
});

app.get('/login', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Login</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Login</h1>
<nav>[<a href="/signup">Sign up</a>]</nav>
<hr>
<form id="f">
Email<br><input type="email" name="email" required><br>
Password<br><input type="password" name="password" required><br>
<button type="submit">Log in</button>
</form>
<p id="err"></p>
</div>
<script>
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const d=Object.fromEntries(new FormData(e.target));
  const r=await fetch('/api/v1/enter',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  const j=await r.json();
  localStorage.setItem('accessToken',j.accessToken);
  localStorage.setItem('refreshToken',j.refreshToken);
  window.location.href='/';
};
</script>
</body></html>`);
});

app.get('/signup', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Sign up</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Sign up</h1>
<nav>[<a href="/login">Log in</a>]</nav>
<hr>
<form id="f">
Nickname<br><input type="text" name="nickname" minlength="2" maxlength="32" required><br>
Email<br><input type="email" name="email" required><br>
Password<br><input type="password" name="password" minlength="8" maxlength="128" required><br>
Role<br><select name="role"><option value="member">Member</option><option value="admin">Admin</option></select><br><br>
<button type="submit">Sign up</button>
</form>
<p id="err"></p>
</div>
<script>
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const d=Object.fromEntries(new FormData(e.target));
  const r=await fetch('/api/v1/join',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  document.getElementById('err').textContent='';
  window.location.href='/login';
};
</script>
</body></html>`);
});

// --- docs ---

const DOCS_DIR = path.join(import.meta.dirname, '..', 'docs');

app.get('/docs/openapi.yml', (_req: Request, res: Response) => {
  res
    .type('text/yaml')
    .send(fs.readFileSync(path.join(DOCS_DIR, 'openapi.yml'), 'utf-8'));
});

app.get('/docs', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head>
<title>Events API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head><body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({ url: "/docs/openapi.yml", dom_id: "#swagger-ui" })</script>
</body></html>`);
});

export { app, pool };

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(import.meta.filename);

if (isMain) {
  await validateMigrations(pool);
  app.listen(PORT, () => {
    console.log(`listening on :${PORT}`);
  });
}
