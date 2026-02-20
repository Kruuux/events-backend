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
  humanId: number,
  expiresAt: Date,
): Promise<string> {
  const refreshToken = jwt.sign({ sub: humanId, type: 'refresh' }, JWT_SECRET, {
    expiresIn: '1h',
  });
  await pool.query(
    'INSERT INTO sessions (human_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [humanId, hashToken(refreshToken), expiresAt],
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

const IdParamSchema = v.object({
  id: v.pipe(v.string(), v.regex(/^\d+$/)),
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

app.post('/join', async (req: Request, res: Response) => {
  const data = validate(JoinSchema, req.body, res);
  if (!data) return;

  const { nickname, email, password, role } = data;

  const emailCheck = await pool.query(
    'SELECT id FROM humans WHERE email = $1',
    [email],
  );
  if (emailCheck.rows.length > 0) {
    res.status(409).json({ error: 'account already taken' });
    return;
  }

  const nicknameCheck = await pool.query(
    'SELECT id FROM humans WHERE nickname = $1',
    [nickname],
  );
  if (nicknameCheck.rows.length > 0) {
    res.status(409).json({ error: 'nickname already taken' });
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
    'INSERT INTO humans (nickname, email, password_hash, salt, role) VALUES ($1, $2, $3, $4, $5)',
    [nickname, email, hash, salt, role],
  );

  res.status(201).json({ message: 'account created' });
});

const EnterSchema = v.object({
  email: v.pipe(v.string(), v.email()),
  password: v.string(),
});

app.post('/enter', async (req: Request, res: Response) => {
  const data = validate(EnterSchema, req.body, res);
  if (!data) return;

  const { email, password } = data;

  const humanResult = await pool.query(
    'SELECT id, password_hash, salt, role FROM humans WHERE email = $1',
    [email],
  );

  if (humanResult.rows.length === 0) {
    res.status(401).json({ error: 'invalid credentials' });
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
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }

  const accessToken = jwt.sign(
    { sub: human.id, role: human.role },
    JWT_SECRET,
    { expiresIn: '15m' },
  );
  const refreshToken = await createSession(
    human.id as number,
    new Date(Date.now() + 60 * 60 * 1000),
  );

  res.status(200).json({ accessToken, refreshToken });
});

const RefreshSchema = v.object({
  refreshToken: v.string(),
});

app.post('/refresh', async (req: Request, res: Response) => {
  const data = validate(RefreshSchema, req.body, res);
  if (!data) return;

  let payload: jwt.JwtPayload;
  try {
    payload = jwt.verify(data.refreshToken, JWT_SECRET) as jwt.JwtPayload;
  } catch {
    res.status(401).json({ error: 'invalid refresh token' });
    return;
  }

  if (payload.type !== 'refresh') {
    res.status(401).json({ error: 'invalid refresh token' });
    return;
  }

  const oldHash = hashToken(data.refreshToken);
  const session = await pool.query(
    'DELETE FROM sessions WHERE token_hash = $1 RETURNING human_id',
    [oldHash],
  );

  if (session.rows.length === 0) {
    res.status(401).json({ error: 'invalid refresh token' });
    return;
  }

  const humanId = session.rows[0]!.human_id as number;

  const humanResult = await pool.query(
    'SELECT role FROM humans WHERE id = $1',
    [humanId],
  );
  const role = humanResult.rows[0]?.role as string;

  const accessToken = jwt.sign({ sub: humanId, role }, JWT_SECRET, {
    expiresIn: '15m',
  });
  const refreshToken = await createSession(
    humanId,
    new Date(Date.now() + 60 * 60 * 1000),
  );

  res.status(200).json({ accessToken, refreshToken });
});

app.post('/logout-all', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ error: 'missing or invalid token' });
    return;
  }

  await pool.query('DELETE FROM sessions WHERE human_id = $1', [payload.sub]);

  res.status(200).json({ message: 'all sessions ended' });
});

// --- organisations ---

const CreateOrganisationSchema = v.object({
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
});

app.post('/organisations', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ error: 'missing or invalid token' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ error: 'admin only' });
    return;
  }

  const data = validate(CreateOrganisationSchema, req.body, res);
  if (!data) return;

  const nameCheck = await pool.query(
    'SELECT id FROM organisations WHERE name = $1',
    [data.name],
  );
  if (nameCheck.rows.length > 0) {
    res.status(409).json({ error: 'organisation name already taken' });
    return;
  }

  const row = await pool.query(
    `INSERT INTO organisations (human_id, name)
     VALUES ($1, $2)
     RETURNING id, human_id AS "humanId", name, created_at AS "createdAt"`,
    [payload.sub, data.name],
  );

  res.status(201).json(row.rows[0]);
});

app.get('/organisations', async (req: Request, res: Response) => {
  const query = validate(PaginationSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const [countResult, rows] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM organisations'),
    pool.query(
      `SELECT id, human_id AS "humanId", name, created_at AS "createdAt"
       FROM organisations ORDER BY name ASC LIMIT $1 OFFSET $2`,
      [limit, offset],
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);

  res.status(200).json({ data: rows.rows, total, page, limit });
});

const UpdateOrganisationSchema = v.object({
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
});

app.put('/organisations/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ error: 'missing or invalid token' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ error: 'admin only' });
    return;
  }

  const data = validate(UpdateOrganisationSchema, req.body, res);
  if (!data) return;

  const nameCheck = await pool.query(
    'SELECT id FROM organisations WHERE name = $1 AND id != $2',
    [data.name, params.id],
  );
  if (nameCheck.rows.length > 0) {
    res.status(409).json({ error: 'organisation name already taken' });
    return;
  }

  const row = await pool.query(
    `UPDATE organisations SET name = $1 WHERE id = $2
     RETURNING id, human_id AS "humanId", name, created_at AS "createdAt"`,
    [data.name, params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ error: 'organisation not found' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.delete('/organisations/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ error: 'missing or invalid token' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ error: 'admin only' });
    return;
  }

  const row = await pool.query(
    'DELETE FROM organisations WHERE id = $1 RETURNING id',
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ error: 'organisation not found' });
    return;
  }

  res.status(200).json({ message: 'organisation deleted' });
});

// --- organisers ---

const OrganiserParamSchema = v.object({
  organisationId: v.pipe(v.string(), v.regex(/^\d+$/)),
});

const AssignOrganiserSchema = v.object({
  humanId: v.number(),
});

const UnassignOrganiserParamSchema = v.object({
  organisationId: v.pipe(v.string(), v.regex(/^\d+$/)),
  humanId: v.pipe(v.string(), v.regex(/^\d+$/)),
});

app.post(
  '/organisations/:organisationId/organisers',
  async (req: Request, res: Response) => {
    const params = validate(OrganiserParamSchema, req.params, res);
    if (!params) return;

    const payload = authenticate(req);
    if (!payload) {
      res.status(401).json({ error: 'missing or invalid token' });
      return;
    }
    if (payload.role !== 'admin') {
      res.status(403).json({ error: 'admin only' });
      return;
    }

    const data = validate(AssignOrganiserSchema, req.body, res);
    if (!data) return;

    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [params.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ error: 'organisation not found' });
      return;
    }

    const humanCheck = await pool.query('SELECT id FROM humans WHERE id = $1', [
      data.humanId,
    ]);
    if (humanCheck.rows.length === 0) {
      res.status(404).json({ error: 'human not found' });
      return;
    }

    const existingCheck = await pool.query(
      'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
      [data.humanId, params.organisationId],
    );
    if (existingCheck.rows.length > 0) {
      res.status(409).json({ error: 'human is already an organiser' });
      return;
    }

    const row = await pool.query(
      `INSERT INTO organisers (human_id, organisation_id)
       VALUES ($1, $2)
       RETURNING id, human_id AS "humanId", organisation_id AS "organisationId", created_at AS "createdAt"`,
      [data.humanId, params.organisationId],
    );

    res.status(201).json(row.rows[0]);
  },
);

app.delete(
  '/organisations/:organisationId/organisers/:humanId',
  async (req: Request, res: Response) => {
    const params = validate(UnassignOrganiserParamSchema, req.params, res);
    if (!params) return;

    const payload = authenticate(req);
    if (!payload) {
      res.status(401).json({ error: 'missing or invalid token' });
      return;
    }
    if (payload.role !== 'admin') {
      res.status(403).json({ error: 'admin only' });
      return;
    }

    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [params.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ error: 'organisation not found' });
      return;
    }

    const humanCheck = await pool.query('SELECT id FROM humans WHERE id = $1', [
      params.humanId,
    ]);
    if (humanCheck.rows.length === 0) {
      res.status(404).json({ error: 'human not found' });
      return;
    }

    const row = await pool.query(
      'DELETE FROM organisers WHERE human_id = $1 AND organisation_id = $2 RETURNING id',
      [params.humanId, params.organisationId],
    );

    if (row.rows.length === 0) {
      res.status(409).json({ error: 'human is not an organiser' });
      return;
    }

    res.status(200).json({ message: 'organiser removed' });
  },
);

// --- events ---

const CreateEventSchema = v.object({
  title: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  description: v.string(),
  latitude: v.pipe(v.number(), v.minValue(-90), v.maxValue(90)),
  longitude: v.pipe(v.number(), v.minValue(-180), v.maxValue(180)),
  startDate: v.pipe(v.string(), v.isoTimestamp()),
  endDate: v.pipe(v.string(), v.isoTimestamp()),
  organisationId: v.optional(v.number()),
});

app.post('/events', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ error: 'missing or invalid token' });
    return;
  }

  const data = validate(CreateEventSchema, req.body, res);
  if (!data) return;

  if (data.organisationId != null) {
    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [data.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ error: 'organisation not found' });
      return;
    }

    if (payload.role !== 'admin') {
      const organiserCheck = await pool.query(
        'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
        [payload.sub, data.organisationId],
      );
      if (organiserCheck.rows.length === 0) {
        res
          .status(403)
          .json({ error: 'not an organiser of this organisation' });
        return;
      }
    }
  }

  const row = await pool.query(
    `INSERT INTO events (human_id, organisation_id, title, description, latitude, longitude, start_date, end_date)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, human_id AS "humanId", organisation_id AS "organisationId", title, description, latitude, longitude, start_date AS "startDate", end_date AS "endDate", created_at AS "createdAt"`,
    [
      payload.sub,
      data.organisationId ?? null,
      data.title,
      data.description,
      data.latitude,
      data.longitude,
      data.startDate,
      data.endDate,
    ],
  );

  res.status(201).json(row.rows[0]);
});

app.get('/events', async (req: Request, res: Response) => {
  const query = validate(PaginationSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const [countResult, rows] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM events'),
    pool.query(
      `SELECT id, human_id AS "humanId", organisation_id AS "organisationId", title, description, latitude, longitude, start_date AS "startDate", end_date AS "endDate", created_at AS "createdAt"
       FROM events ORDER BY start_date ASC LIMIT $1 OFFSET $2`,
      [limit, offset],
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);

  res.status(200).json({ data: rows.rows, total, page, limit });
});

app.get('/events/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    `SELECT id, human_id AS "humanId", organisation_id AS "organisationId", title, description, latitude, longitude, start_date AS "startDate", end_date AS "endDate", created_at AS "createdAt"
     FROM events WHERE id = $1`,
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ error: 'event not found' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

const UpdateEventSchema = v.object({
  title: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  description: v.string(),
  latitude: v.pipe(v.number(), v.minValue(-90), v.maxValue(90)),
  longitude: v.pipe(v.number(), v.minValue(-180), v.maxValue(180)),
  startDate: v.pipe(v.string(), v.isoTimestamp()),
  endDate: v.pipe(v.string(), v.isoTimestamp()),
  organisationId: v.optional(v.nullable(v.number())),
});

app.put('/events/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ error: 'missing or invalid token' });
    return;
  }

  const data = validate(UpdateEventSchema, req.body, res);
  if (!data) return;

  if (data.organisationId != null) {
    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [data.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ error: 'organisation not found' });
      return;
    }

    if (payload.role !== 'admin') {
      const organiserCheck = await pool.query(
        'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
        [payload.sub, data.organisationId],
      );
      if (organiserCheck.rows.length === 0) {
        res
          .status(403)
          .json({ error: 'not an organiser of this organisation' });
        return;
      }
    }
  }

  const row = await pool.query(
    `UPDATE events SET title = $1, description = $2, latitude = $3, longitude = $4, start_date = $5, end_date = $6, organisation_id = $7
     WHERE id = $8
     RETURNING id, human_id AS "humanId", organisation_id AS "organisationId", title, description, latitude, longitude, start_date AS "startDate", end_date AS "endDate", created_at AS "createdAt"`,
    [
      data.title,
      data.description,
      data.latitude,
      data.longitude,
      data.startDate,
      data.endDate,
      data.organisationId ?? null,
      params.id,
    ],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ error: 'event not found' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

app.delete('/events/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    'DELETE FROM events WHERE id = $1 RETURNING id',
    [params.id],
  );

  if (row.rows.length === 0) {
    res.status(404).json({ error: 'event not found' });
    return;
  }

  res.status(200).json({ message: 'event deleted' });
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

await validateMigrations(pool);

app.listen(PORT, () => {
  console.log(`listening on :${PORT}`);
});
