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
    'INSERT INTO humans (nickname, email, password_hash, salt, role) VALUES ($1, $2, $3, $4, $5)',
    [nickname, email, hash, salt, role],
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
    { sub: human.id, role: human.role, nickname: human.nickname, email: human.email },
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

  const humanId = session.rows[0]!.human_id as number;

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
  id: v.pipe(v.string(), v.regex(/^\d+$/)),
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
    res.status(403).json({ code: 'ADMIN_ONLY_EXCEPTION' });
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
  organisationId: v.pipe(v.string(), v.regex(/^\d+$/)),
  humanId: v.number(),
});

const UnassignOrganiserSchema = v.object({
  organisationId: v.pipe(v.string(), v.regex(/^\d+$/)),
  humanId: v.pipe(v.string(), v.regex(/^\d+$/)),
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
      res.status(403).json({ code: 'ADMIN_ONLY_EXCEPTION' });
      return;
    }

    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [data.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    const humanCheck = await pool.query('SELECT id FROM humans WHERE id = $1', [
      data.humanId,
    ]);
    if (humanCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
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

    const row = await pool.query(
      `INSERT INTO organisers (human_id, organisation_id)
       VALUES ($1, $2)
       RETURNING id, human_id AS "humanId", organisation_id AS "organisationId", created_at AS "createdAt"`,
      [data.humanId, data.organisationId],
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
      res.status(403).json({ code: 'ADMIN_ONLY_EXCEPTION' });
      return;
    }

    const orgCheck = await pool.query(
      'SELECT id FROM organisations WHERE id = $1',
      [data.organisationId],
    );
    if (orgCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
    }

    const humanCheck = await pool.query('SELECT id FROM humans WHERE id = $1', [
      data.humanId,
    ]);
    if (humanCheck.rows.length === 0) {
      res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
      return;
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
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).json(row.rows[0]);
});

const UpdateEventSchema = v.object({
  id: v.pipe(v.string(), v.regex(/^\d+$/)),
  title: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  description: v.string(),
  latitude: v.pipe(v.number(), v.minValue(-90), v.maxValue(90)),
  longitude: v.pipe(v.number(), v.minValue(-180), v.maxValue(180)),
  startDate: v.pipe(v.string(), v.isoTimestamp()),
  endDate: v.pipe(v.string(), v.isoTimestamp()),
  organisationId: v.optional(v.nullable(v.number())),
});

app.put('/events/:id', async (req: Request, res: Response) => {
  const data = validate(UpdateEventSchema, { ...req.params, ...req.body }, res);
  if (!data) return;

  const payload = authenticate(req);
  if (!payload) {
    res.status(401).json({ code: 'UNAUTHORIZED_EXCEPTION' });
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

  if (row.rows.length === 0) {
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
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
    res.status(404).json({ code: 'RESOURCE_NOT_FOUND_EXCEPTION' });
    return;
  }

  res.status(200).end();
});

// --- pages ---

const PAGE_STYLE = `*{margin:0;padding:0;box-sizing:border-box}body{background:#fff;color:#000;font-family:monospace;font-size:16px}.c{max-width:1000px;margin:0 auto;padding:24px 16px}a{color:#000}nav{margin:8px 0 16px}hr{border:none;border-top:1px solid #000;margin:16px 0}input,select{border:1px solid #000;padding:6px;margin:4px 0 12px;width:100%;font-family:monospace;font-size:16px}button{border:1px solid #000;background:#fff;color:#000;padding:6px 16px;font-family:monospace;font-size:16px;cursor:pointer}#err{font-weight:bold;margin-top:12px}`;
const PAGE_HEAD = `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${PAGE_STYLE}</style>`;
const APP_NAV = `<nav>[<a href="/">Events</a>] [<a href="/create-event">Create event</a>] [<a href="/profile">Profile</a>]</nav>`;

app.get('/', (_req: Request, res: Response) => {
  res.type('html').send(`<!DOCTYPE html>
<html><head><title>Events</title>${PAGE_HEAD}<style>#end{display:none}</style></head><body>
<div class="c">
<h1>Events</h1>
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
  const r=await fetch('/events?page='+page+'&limit='+limit);
  if(!r.ok){loading=false;document.getElementById('loading').style.display='none';return}
  const j=await r.json();
  const list=document.getElementById('list');
  for(const ev of j.data){
    const d=document.createElement('div');
    d.innerHTML='<b>'+esc(ev.title)+'</b><br>'
      +esc(ev.description)+'<br>'
      +'<small>'+new Date(ev.startDate).toLocaleString()+' - '+new Date(ev.endDate).toLocaleString()+'</small><hr>';
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
Organisation ID (optional)<br><input type="number" name="organisationId"><br><br>
<button type="submit">Create</button>
</form>
<p id="err"></p>
</div>
<script>
if(!localStorage.getItem('accessToken'))window.location.href='/login';
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();
  const fd=Object.fromEntries(new FormData(e.target));
  const body={title:fd.title,description:fd.description,latitude:Number(fd.latitude),longitude:Number(fd.longitude),startDate:new Date(fd.startDate).toISOString(),endDate:new Date(fd.endDate).toISOString()};
  if(fd.organisationId)body.organisationId=Number(fd.organisationId);
  const r=await fetch('/events',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('accessToken')},body:JSON.stringify(body)});
  if(!r.ok){const j=await r.json();document.getElementById('err').textContent=j.code||JSON.stringify(j);return}
  window.location.href='/';
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
