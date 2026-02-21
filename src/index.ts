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

app.post('/join', async (req: Request, res: Response) => {
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

app.post('/enter', async (req: Request, res: Response) => {
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

app.post('/refresh', async (req: Request, res: Response) => {
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

app.post('/logout-all', async (req: Request, res: Response) => {
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

app.get('/humans', async (req: Request, res: Response) => {
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

app.post('/organisations', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'ADMIN_ONLY_EXCEPTION' });
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
});

app.get('/organisations', async (req: Request, res: Response) => {
  const query = validate(OrganisationListSchema, req.query, res);
  if (!query) return;

  const page = Math.max(1, Number(query.page));
  const limit = Math.min(100, Math.max(1, Number(query.limit)));
  const offset = (page - 1) * limit;

  const where = query.name ? `WHERE name ILIKE '%' || $3 || '%'` : '';
  const params = query.name ? [limit, offset, query.name] : [limit, offset];
  const countParams = query.name ? [query.name] : [];
  const countWhere = query.name ? `WHERE name ILIKE '%' || $1 || '%'` : '';

  const [countResult, rows] = await Promise.all([
    pool.query(`SELECT COUNT(*) FROM organisations ${countWhere}`, countParams),
    pool.query(
      `SELECT id, human_id AS "humanId", name, created_at AS "createdAt"
       FROM organisations ${where} ORDER BY name ASC LIMIT $1 OFFSET $2`,
      params,
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);

  res.status(200).json({ data: rows.rows, total, page, limit });
});

app.get('/organisations/:id', async (req: Request, res: Response) => {
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

  const org = row.rows[0]!;
  const payload = authenticate(req);
  let isOrganiser = false;
  if (payload) {
    if (payload.role === 'admin') {
      isOrganiser = true;
    } else {
      const check = await pool.query(
        'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
        [payload.sub, params.id],
      );
      isOrganiser = check.rows.length > 0;
    }
  }

  res.status(200).json({ ...org, isOrganiser });
});

const UpdateOrganisationSchema = v.object({
  id: UuidSchema,
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
});

app.put('/organisations/:id', async (req: Request, res: Response) => {
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
    const organiserCheck = await pool.query(
      'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
      [payload.sub, data.id],
    );
    if (organiserCheck.rows.length === 0) {
      res.status(403).json({ code: 'ADMIN_ONLY_EXCEPTION' });
      return;
    }
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

app.delete('/organisations/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }
  if (payload.role !== 'admin') {
    res.status(403).json({ code: 'ADMIN_ONLY_EXCEPTION' });
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

// --- organisers ---

const AssignOrganiserSchema = v.object({
  organisationId: UuidSchema,
  humanId: UuidSchema,
});

const UnassignOrganiserSchema = v.object({
  organisationId: UuidSchema,
  humanId: UuidSchema,
});

app.post(
  '/organisations/:organisationId/organisers',
  async (req: Request, res: Response) => {
    const data = validate(
      AssignOrganiserSchema,
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
      const selfCheck = await pool.query(
        'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
        [payload.sub, data.organisationId],
      );
      if (selfCheck.rows.length === 0) {
        res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
        return;
      }
    }

    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [data.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    const humanCheck = await pool.query(
      'SELECT id, role FROM humans WHERE id = $1',
      [data.humanId],
    );
    if (humanCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    if (humanCheck.rows[0]!.role === 'admin') {
      res.status(400).json({ code: 'CANNOT_ADD_ADMIN_AS_ORGANISER_EXCEPTION' });
      return;
    }

    const existingCheck = await pool.query(
      'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
      [data.humanId, data.organisationId],
    );
    if (existingCheck.rows.length > 0) {
      res.status(409).json({ code: 'ALREADY_ORGANISER_EXCEPTION' });
      return;
    }

    const countCheck = await pool.query(
      'SELECT COUNT(*) AS cnt FROM organisers WHERE organisation_id = $1',
      [data.organisationId],
    );
    if (Number(countCheck.rows[0]!.cnt) >= 5) {
      res.status(400).json({ code: 'MAX_ORGANISERS_REACHED_EXCEPTION' });
      return;
    }

    const row = await pool.query(
      `INSERT INTO organisers (id, human_id, organisation_id)
       VALUES ($1, $2, $3)
       RETURNING id, human_id AS "humanId", organisation_id AS "organisationId", created_at AS "createdAt"`,
      [crypto.randomUUID(), data.humanId, data.organisationId],
    );

    res.status(201).json(row.rows[0]);
  },
);

app.delete(
  '/organisations/:organisationId/organisers/:humanId',
  async (req: Request, res: Response) => {
    const data = validate(UnassignOrganiserSchema, req.params, res);
    if (!data) return;

    const payload = authenticate(req);
    if (!payload) {
      res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
      return;
    }

    if (payload.role !== 'admin') {
      const selfCheck = await pool.query(
        'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
        [payload.sub, data.organisationId],
      );
      if (selfCheck.rows.length === 0) {
        res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
        return;
      }

      // members can only remove themselves or other non-first organisers
      if (data.humanId !== payload.sub) {
        const firstOrganiser = await pool.query(
          'SELECT human_id FROM organisers WHERE organisation_id = $1 ORDER BY created_at ASC LIMIT 1',
          [data.organisationId],
        );
        if (
          firstOrganiser.rows.length > 0 &&
          firstOrganiser.rows[0]!.human_id === data.humanId
        ) {
          res
            .status(403)
            .json({ code: 'CANNOT_REMOVE_FIRST_ORGANISER_EXCEPTION' });
          return;
        }
      }
    }

    const row = await pool.query(
      'DELETE FROM organisers WHERE human_id = $1 AND organisation_id = $2 RETURNING id',
      [data.humanId, data.organisationId],
    );

    if (row.rows.length === 0) {
      res.status(409).json({ code: 'NOT_AN_ORGANISER_EXCEPTION' });
      return;
    }

    res.status(200).end();
  },
);

app.get(
  '/organisations/:organisationId/organisers',
  async (req: Request, res: Response) => {
    const payload = authenticate(req);
    if (!payload) {
      res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
      return;
    }

    const organisationId = req.params.organisationId;

    if (payload.role !== 'admin') {
      const selfCheck = await pool.query(
        'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
        [payload.sub, organisationId],
      );
      if (selfCheck.rows.length === 0) {
        res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
        return;
      }
    }

    const rows = await pool.query(
      `SELECT o.id, o.human_id AS "humanId", o.organisation_id AS "organisationId",
              o.created_at AS "createdAt", h.nickname
       FROM organisers o JOIN humans h ON h.id = o.human_id
       WHERE o.organisation_id = $1
       ORDER BY o.created_at ASC`,
      [organisationId],
    );

    res.status(200).json(rows.rows);
  },
);

app.get(
  '/organisations/:organisationId/organisers/check',
  async (req: Request, res: Response) => {
    const humanId = req.query.humanId as string;
    if (!humanId) {
      res.status(400).json({
        code: 'VALIDATION_EXCEPTION',
        violations: [{ property: 'humanId', message: 'Required' }],
      });
      return;
    }
    const organisationId = req.params.organisationId;
    const row = await pool.query(
      'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
      [humanId, organisationId],
    );
    res.status(200).json({ isOrganiser: row.rows.length > 0 });
  },
);

app.get(
  '/organisations/:organisationId/events',
  async (req: Request, res: Response) => {
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
                e.title, e.description, e.latitude, e.longitude,
                e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
                o.name AS "organisationName"
         FROM events e LEFT JOIN organisations o ON o.id = e.organisation_id
         WHERE e.organisation_id = $1
         ORDER BY CASE WHEN e.start_date >= CURRENT_DATE THEN 0 ELSE 1 END,
                  CASE WHEN e.start_date >= CURRENT_DATE THEN e.start_date END ASC,
                  CASE WHEN e.start_date < CURRENT_DATE THEN e.start_date END DESC
         LIMIT $2 OFFSET $3`,
        [organisationId, limit, offset],
      ),
    ]);

    const total = Number(countResult.rows[0]!.count);
    res.status(200).json({ data: rows.rows, total, page, limit });
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
  organisationId: v.optional(UuidSchema),
});

app.post('/events', async (req: Request, res: Response) => {
  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
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
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    if (payload.role !== 'admin') {
      const organiserCheck = await pool.query(
        'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
        [payload.sub, data.organisationId],
      );
      if (organiserCheck.rows.length === 0) {
        res.status(403).json({ code: 'NOT_ORGANISER_EXCEPTION' });
        return;
      }
    }
  }

  const eventId = crypto.randomUUID();
  const row = await pool.query(
    `INSERT INTO events (id, human_id, organisation_id, title, description, latitude, longitude, start_date, end_date)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING id, human_id AS "humanId", organisation_id AS "organisationId", title, description, latitude, longitude, start_date AS "startDate", end_date AS "endDate", created_at AS "createdAt"`,
    [
      eventId,
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
    pool.query('SELECT COUNT(*) FROM events WHERE start_date >= CURRENT_DATE'),
    pool.query(
      `SELECT e.id, e.human_id AS "humanId", e.organisation_id AS "organisationId",
              e.title, e.description, e.latitude, e.longitude,
              e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
              o.name AS "organisationName"
       FROM events e LEFT JOIN organisations o ON o.id = e.organisation_id
       WHERE e.start_date >= CURRENT_DATE
       ORDER BY e.start_date ASC LIMIT $1 OFFSET $2`,
      [limit, offset],
    ),
  ]);

  const total = Number(countResult.rows[0]!.count);

  res.status(200).json({ data: rows.rows, total, page, limit });
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

app.get('/events/area', async (req: Request, res: Response) => {
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
            e.title, e.description, e.latitude, e.longitude,
            e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
            o.name AS "organisationName"
     FROM events e LEFT JOIN organisations o ON o.id = e.organisation_id
     WHERE e.start_date >= CURRENT_DATE
       AND e.latitude >= $1 AND e.latitude <= $2
       AND e.longitude >= $3 AND e.longitude <= $4
     ORDER BY e.start_date ASC`,
    [query.minLat, query.maxLat, query.minLng, query.maxLng],
  );

  res.status(200).json({ data: rows.rows });
});

app.get('/events/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const row = await pool.query(
    `SELECT e.id, e.human_id AS "humanId", e.organisation_id AS "organisationId",
            e.title, e.description, e.latitude, e.longitude,
            e.start_date AS "startDate", e.end_date AS "endDate", e.created_at AS "createdAt",
            o.name AS "organisationName"
     FROM events e LEFT JOIN organisations o ON o.id = e.organisation_id
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
  latitude: v.pipe(v.number(), v.minValue(-90), v.maxValue(90)),
  longitude: v.pipe(v.number(), v.minValue(-180), v.maxValue(180)),
  startDate: v.pipe(v.string(), v.isoTimestamp()),
  endDate: v.pipe(v.string(), v.isoTimestamp()),
  organisationId: v.optional(v.nullable(UuidSchema)),
});

app.put('/events/:id', async (req: Request, res: Response) => {
  const data = validate(UpdateEventSchema, { ...req.params, ...req.body }, res);
  if (!data) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const existing = await pool.query(
    'SELECT human_id, organisation_id FROM events WHERE id = $1',
    [data.id],
  );
  if (existing.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  const ev = existing.rows[0]!;
  if (payload.role !== 'admin' && payload.sub !== ev.human_id) {
    if (!ev.organisation_id) {
      res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
      return;
    }
    const organiserCheck = await pool.query(
      'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
      [payload.sub, ev.organisation_id],
    );
    if (organiserCheck.rows.length === 0) {
      res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
      return;
    }
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
      data.id,
    ],
  );

  res.status(200).json(row.rows[0]);
});

app.delete('/events/:id', async (req: Request, res: Response) => {
  const params = validate(IdParamSchema, req.params, res);
  if (!params) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
    return;
  }

  const existing = await pool.query(
    'SELECT human_id, organisation_id FROM events WHERE id = $1',
    [params.id],
  );
  if (existing.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  const ev = existing.rows[0]!;
  if (payload.role !== 'admin' && payload.sub !== ev.human_id) {
    if (!ev.organisation_id) {
      res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
      return;
    }
    const organiserCheck = await pool.query(
      'SELECT id FROM organisers WHERE human_id = $1 AND organisation_id = $2',
      [payload.sub, ev.organisation_id],
    );
    if (organiserCheck.rows.length === 0) {
      res.status(403).json({ code: 'FORBIDDEN_EXCEPTION' });
      return;
    }
  }

  await pool.query('DELETE FROM events WHERE id = $1', [params.id]);

  res.status(200).end();
});

// --- pages ---

const PAGE_STYLE = `*{margin:0;padding:0;box-sizing:border-box}body{background:#fff;color:#000;font-family:monospace;font-size:16px}.c{max-width:1000px;margin:0 auto;padding:24px 16px}a{color:#000}nav{margin:8px 0 16px}hr{border:none;border-top:1px solid #000;margin:16px 0}input,select{border:1px solid #000;padding:6px;margin:4px 0 12px;width:100%;font-family:monospace;font-size:16px}button{border:1px solid #000;background:#fff;color:#000;padding:6px 16px;font-family:monospace;font-size:16px;cursor:pointer}#err{font-weight:bold;margin-top:12px}.dropdown{border:1px solid #000;max-height:150px;overflow-y:auto;display:none}.dropdown div{padding:4px 6px;cursor:pointer}.dropdown div:hover{background:#000;color:#fff}`;
const PAGE_HEAD = `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${PAGE_STYLE}</style>`;
const NAV_SCRIPT = `<script>
(function(){const t=localStorage.getItem('accessToken');if(!t)return;
try{const p=JSON.parse(atob(t.split('.')[1]));
if(p.role==='admin'){const s=document.getElementById('adminNav');if(s)s.style.display='inline'}}catch{}})();
</script>`;
const APP_NAV = `<nav>[<a href="/">Events</a>] [<a href="/organisations-list">Organisations</a>] [<a href="/create-event">Create event</a>] <span id="adminNav" style="display:none">[<a href="/create-organisation">Create organisation</a>] </span>[<a href="/profile">Profile</a>]</nav>${NAV_SCRIPT}`;

const ORG_SEARCH_HTML = `Organisation (optional)<br><input type="text" id="orgSearch" placeholder="Search by name..." autocomplete="off"><input type="hidden" name="organisationId" id="orgId"><div class="dropdown" id="orgDrop"></div>`;
const ORG_SEARCH_SCRIPT = `
let debounce;
document.getElementById('orgSearch').oninput=function(){
  clearTimeout(debounce);
  const v=this.value;
  const drop=document.getElementById('orgDrop');
  if(v.length<2){drop.style.display='none';document.getElementById('orgId').value='';return}
  debounce=setTimeout(async()=>{
    const r=await fetch('/organisations?name='+encodeURIComponent(v)+'&limit=10');
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

// --- list view ---
let page=1;const limit=20;let loading=false;let done=false;
let lastDateLabel='';
function dateLabel(ds){
  const d=new Date(ds);
  const now=new Date();
  const today=new Date(now.getFullYear(),now.getMonth(),now.getDate());
  const tmrw=new Date(today);tmrw.setDate(tmrw.getDate()+1);
  const dayAfter=new Date(today);dayAfter.setDate(dayAfter.getDate()+2);
  const t=new Date(d.getFullYear(),d.getMonth(),d.getDate());
  if(t.getTime()===today.getTime())return 'Today';
  if(t.getTime()===tmrw.getTime())return 'Tomorrow';
  return d.getDate()+' '+d.toLocaleString('en',{month:'long'})+' '+d.getFullYear();
}
async function load(){
  if(loading||done)return;
  loading=true;
  document.getElementById('loading').style.display='block';
  const r=await fetch('/events?page='+page+'&limit='+limit);
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
    const d=document.createElement('div');
    let evHtml='<a href="/view/event/'+ev.id+'"><b>'+esc(ev.title)+'</b></a><br>'
      +esc(ev.description)+'<br>';
    if(ev.organisationName)evHtml+='<small>Organisation: <a href="/view/organisation/'+ev.organisationId+'">'+esc(ev.organisationName)+'</a></small><br>';
    evHtml+='<hr>';
    d.innerHTML=evHtml;
    list.appendChild(d);
  }
  if(page*limit>=j.total){done=true;document.getElementById('end').style.display='block'}
  else{page++}
  loading=false;
  document.getElementById('loading').style.display=done?'none':'block';
}
window.addEventListener('scroll',()=>{
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-200)load();
});
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

  const r=await fetch('/events/area?minLat='+minLat+'&maxLat='+maxLat+'&minLng='+minLng+'&maxLng='+maxLng);
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
<html><head><title>Organisations</title>${PAGE_HEAD}<style>#end{display:none}</style></head><body>
<div class="c">
<h1>Organisations</h1>
${APP_NAV}
<hr>
<div id="list"></div>
<p id="loading">Loading...</p>
<p id="end">---</p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
let page=1;const limit=20;let loading=false;let done=false;
async function load(){
  if(loading||done)return;
  loading=true;
  document.getElementById('loading').style.display='block';
  const r=await fetch('/organisations?page='+page+'&limit='+limit);
  if(!r.ok){loading=false;document.getElementById('loading').style.display='none';return}
  const j=await r.json();
  const list=document.getElementById('list');
  for(const o of j.data){
    const d=document.createElement('div');
    d.innerHTML='<a href="/view/organisation/'+o.id+'"><b>'+esc(o.name)+'</b></a><br>'
      +'<small>Created: '+new Date(o.createdAt).toLocaleString()+'</small><hr>';
    list.appendChild(d);
  }
  if(page*limit>=j.total){done=true;document.getElementById('end').style.display='block'}
  else{page++}
  loading=false;
  document.getElementById('loading').style.display=done?'none':'block';
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
window.addEventListener('scroll',()=>{
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-200)load();
});
load();
</script>
</body></html>`);
});

app.get('/view/event/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Event</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1 id="title">Event</h1>
${APP_NAV}
<hr>
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
  const r=await fetch('/events/'+id);
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const ev=await r.json();
  document.getElementById('title').textContent=ev.title;
  let html='<p>'+esc(ev.description)+'</p>'
    +'<p>Latitude: '+ev.latitude+'</p>'
    +'<p>Longitude: '+ev.longitude+'</p>'
    +'<p>Start: '+new Date(ev.startDate).toLocaleString()+'</p>'
    +'<p>End: '+new Date(ev.endDate).toLocaleString()+'</p>'
    +'<p>Created: '+new Date(ev.createdAt).toLocaleString()+'</p>';
  if(ev.organisationId)html+='<p>Organisation: <a href="/view/organisation/'+ev.organisationId+'">'+esc(ev.organisationName||ev.organisationId)+'</a></p>';
  let canEdit=me.role==='admin'||me.sub===ev.humanId;
  if(!canEdit&&ev.organisationId){
    const cr=await fetch('/organisations/'+ev.organisationId+'/organisers/check?humanId='+me.sub);
    if(cr.ok){const cj=await cr.json();canEdit=cj.isOrganiser}
  }
  if(canEdit)html+='<br><a href="/edit/event/'+ev.id+'">[edit]</a>';
  document.getElementById('detail').innerHTML=html;
})();
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
</script>
</body></html>`);
});

app.get('/view/organisation/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Organisation</title>${PAGE_HEAD}<style>#end{display:none}</style></head><body>
<div class="c">
<h1 id="title">Organisation</h1>
${APP_NAV}
<hr>
<div id="detail"></div>
<p id="err"></p>
<div id="eventsSection" style="display:none">
<h2 style="margin:24px 0 12px">Events</h2>
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
  const r=await fetch('/organisations/'+id,{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const o=await r.json();
  document.getElementById('title').textContent=o.name;
  let html='<p>Name: '+esc(o.name)+'</p>'
    +'<p>Created: '+new Date(o.createdAt).toLocaleString()+'</p>';
  if(o.isOrganiser||me.role==='admin'){
    html+='<br><a href="/edit/organisation/'+o.id+'">[edit]</a>';
    html+=' <a href="/manage/organisation/'+o.id+'/organisers">[manage organisers]</a>';
  }
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
  const r=await fetch('/organisations/'+id+'/events?page='+evPage+'&limit='+evLimit);
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
  if(evPage*evLimit>=j.total){evDone=true;document.getElementById('end').style.display='block'}
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

app.get('/create-event', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Create event</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Create event</h1>
${APP_NAV}
<hr>
<form id="f">
Title<br><input type="text" name="title" required><br>
Description<br><input type="text" name="description" required><br>
Latitude<br><input type="number" name="latitude" step="any" min="-90" max="90" required><br>
Longitude<br><input type="number" name="longitude" step="any" min="-180" max="180" required><br>
Start<br><input type="datetime-local" name="startDate" required><br>
End<br><input type="datetime-local" name="endDate" required><br>
${ORG_SEARCH_HTML}<br>
<button type="submit">Create</button>
</form>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
${ORG_SEARCH_SCRIPT}
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const fd=Object.fromEntries(new FormData(e.target));
  const body={title:fd.title,description:fd.description,latitude:Number(fd.latitude),longitude:Number(fd.longitude),startDate:new Date(fd.startDate).toISOString(),endDate:new Date(fd.endDate).toISOString()};
  if(fd.organisationId)body.organisationId=fd.organisationId;
  const r=await fetch('/events',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('accessToken')},body:JSON.stringify(body)});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  window.location.href='/';
};
</script>
</body></html>`);
});

app.get('/edit/event/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Edit event</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Edit event</h1>
${APP_NAV}
<hr>
<form id="f">
Title<br><input type="text" name="title" required><br>
Description<br><input type="text" name="description" required><br>
Latitude<br><input type="number" name="latitude" step="any" min="-90" max="90" required><br>
Longitude<br><input type="number" name="longitude" step="any" min="-180" max="180" required><br>
Start<br><input type="datetime-local" name="startDate" required><br>
End<br><input type="datetime-local" name="endDate" required><br>
${ORG_SEARCH_HTML}<br>
<button type="submit">Update</button>
</form>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const eventId=window.location.pathname.split('/').pop();
${ORG_SEARCH_SCRIPT}
(async()=>{
  const r=await fetch('/events/'+eventId);
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const ev=await r.json();
  const f=document.getElementById('f');
  f.title.value=ev.title;
  f.description.value=ev.description;
  f.latitude.value=ev.latitude;
  f.longitude.value=ev.longitude;
  f.startDate.value=ev.startDate.slice(0,16);
  f.endDate.value=ev.endDate.slice(0,16);
  if(ev.organisationId){
    document.getElementById('orgId').value=ev.organisationId;
    const or=await fetch('/organisations/'+ev.organisationId);
    if(or.ok){const oj=await or.json();document.getElementById('orgSearch').value=oj.name}
  }
})();
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const fd=Object.fromEntries(new FormData(e.target));
  const body={title:fd.title,description:fd.description,latitude:Number(fd.latitude),longitude:Number(fd.longitude),startDate:new Date(fd.startDate).toISOString(),endDate:new Date(fd.endDate).toISOString()};
  if(fd.organisationId)body.organisationId=fd.organisationId;
  else body.organisationId=null;
  const r=await fetch('/events/'+eventId,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('accessToken')},body:JSON.stringify(body)});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  window.location.href='/view/event/'+eventId;
};
</script>
</body></html>`);
});

app.get('/create-organisation', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Create organisation</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Create organisation</h1>
${APP_NAV}
<hr>
<form id="f">
Name<br><input type="text" name="name" minlength="1" maxlength="256" required><br><br>
<button type="submit">Create</button>
</form>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
try{const p=JSON.parse(atob(localStorage.getItem('accessToken').split('.')[1]));if(p.role!=='admin')window.location.href='/'}catch{window.location.href='/login'}
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const fd=Object.fromEntries(new FormData(e.target));
  const r=await fetch('/organisations',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('accessToken')},body:JSON.stringify({name:fd.name})});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  window.location.href='/organisations-list';
};
</script>
</body></html>`);
});

app.get('/edit/organisation/:id', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Edit organisation</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Edit organisation</h1>
${APP_NAV}
<hr>
<form id="f">
Name<br><input type="text" name="name" minlength="1" maxlength="256" required><br><br>
<button type="submit">Update</button>
</form>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const orgId=window.location.pathname.split('/').pop();
(async()=>{
  const r=await fetch('/organisations/'+orgId);
  if(!r.ok){document.getElementById('err').textContent='Not found';return}
  const o=await r.json();
  document.getElementById('f').name.value=o.name;
})();
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const fd=Object.fromEntries(new FormData(e.target));
  const r=await fetch('/organisations/'+orgId,{method:'PUT',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('accessToken')},body:JSON.stringify({name:fd.name})});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  window.location.href='/view/organisation/'+orgId;
};
</script>
</body></html>`);
});

app.get(
  '/manage/organisation/:id/organisers',
  (_req: Request, res: Response) => {
    res.type('html').send(`<!DOCTYPE html>
<html><head><title>Manage organisers</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1 id="title">Manage organisers</h1>
${APP_NAV}
<hr>
<p><a id="back" href="#">&larr; Back to organisation</a></p>
<br>
<b>Add organiser</b><br>
<input type="text" id="humanSearch" placeholder="Search by nickname..." autocomplete="off">
<div class="dropdown" id="humanDrop"></div>
<br>
<b>Current organisers</b>
<div id="list"></div>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
const parts=window.location.pathname.split('/');
const orgId=parts[3];
const t=localStorage.getItem('accessToken');
let me={};
try{me=JSON.parse(atob(t.split('.')[1]))}catch{}
document.getElementById('back').href='/view/organisation/'+orgId;
let debounce;
document.getElementById('humanSearch').oninput=function(){
  clearTimeout(debounce);
  const v=this.value;
  const drop=document.getElementById('humanDrop');
  if(v.length<2){drop.style.display='none';return}
  debounce=setTimeout(async()=>{
    const r=await fetch('/humans?nickname='+encodeURIComponent(v));
    if(!r.ok)return;
    const humans=await r.json();
    drop.innerHTML='';
    if(humans.length===0){drop.style.display='none';return}
    for(const h of humans){
      const d=document.createElement('div');
      d.textContent=h.nickname;
      d.onclick=async()=>{
        drop.style.display='none';
        document.getElementById('humanSearch').value='';
        const r=await fetch('/organisations/'+orgId+'/organisers',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({humanId:h.id})});
        if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
        document.getElementById('err').textContent='';
        loadOrganisers();
      };
      drop.appendChild(d);
    }
    drop.style.display='block';
  },300);
};
document.addEventListener('click',e=>{if(!e.target.closest('#humanSearch,#humanDrop'))document.getElementById('humanDrop').style.display='none'});
async function loadOrganisers(){
  const r=await fetch('/organisations/'+orgId+'/organisers',{headers:{'Authorization':'Bearer '+t}});
  if(!r.ok){document.getElementById('err').textContent='Could not load organisers';return}
  const organisers=await r.json();
  const list=document.getElementById('list');
  list.innerHTML='';
  const firstId=organisers.length>0?organisers[0].humanId:null;
  for(const o of organisers){
    const d=document.createElement('div');
    let html=esc(o.nickname)+' <small>('+o.humanId.slice(0,8)+'...)</small>';
    const isFirst=o.humanId===firstId;
    const canRemove=me.role==='admin'||(o.humanId===me.sub)||(!isFirst);
    if(canRemove)html+=' <a href="#" class="rm" data-hid="'+o.humanId+'">[remove]</a>';
    if(isFirst)html+=' <small>(first organiser)</small>';
    d.innerHTML=html+'<hr>';
    list.appendChild(d);
  }
  list.querySelectorAll('.rm').forEach(a=>{
    a.onclick=async e=>{
      e.preventDefault();
      const hid=a.dataset.hid;
      const r=await fetch('/organisations/'+orgId+'/organisers/'+hid,{method:'DELETE',headers:{'Authorization':'Bearer '+t}});
      if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
      document.getElementById('err').textContent='';
      loadOrganisers();
    };
  });
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
loadOrganisers();
</script>
</body></html>`);
  },
);

app.get('/profile', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Profile</title>${PAGE_HEAD}</head><body>
<div class="c">
<h1>Profile</h1>
${APP_NAV}
<hr>
<p>Nickname: <b id="nick"></b></p>
<p>Email: <b id="email"></b></p>
<br>
<button id="logout">Log out</button>
</div>
<script>
const t=localStorage.getItem('accessToken');
if(!t){window.location.href='/login'}
else{try{const p=JSON.parse(atob(t.split('.')[1]));document.getElementById('nick').textContent=p.nickname;document.getElementById('email').textContent=p.email}catch{window.location.href='/login'}}
document.getElementById('logout').onclick=()=>{
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  window.location.href='/login';
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
  const r=await fetch('/enter',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
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
  const r=await fetch('/join',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
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

await validateMigrations(pool);

app.listen(PORT, () => {
  console.log(`listening on :${PORT}`);
});
