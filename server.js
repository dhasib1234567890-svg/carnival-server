import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import pg from 'pg';

const { Pool } = pg;
const app = express();

app.use(express.json({ limit: '20mb' }));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('DATABASE_URL is missing. Add it in Render Environment Variables.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

const sessions = new Map();
const SESSION_MS = 12 * 60 * 60 * 1000;

const TABLE_KEYS = [
  'zones',
  'pops',
  'olts',
  'ports',
  'firstSplitters',
  'secondSplitters',
  'clients'
];

const emptyState = () => ({
  users: [],
  zones: [],
  pops: [],
  olts: [],
  ports: [],
  firstSplitters: [],
  secondSplitters: [],
  clients: []
});

function normalizeState(input = {}) {
  return {
    users: Array.isArray(input.users) ? input.users : [],
    zones: Array.isArray(input.zones) ? input.zones : [],
    pops: Array.isArray(input.pops) ? input.pops : [],
    olts: Array.isArray(input.olts) ? input.olts : [],
    ports: Array.isArray(input.ports) ? input.ports : [],
    firstSplitters: Array.isArray(
      input.firstSplitters ?? input.first_splitters
    )
      ? (input.firstSplitters ?? input.first_splitters)
      : [],
    secondSplitters: Array.isArray(
      input.secondSplitters ?? input.second_splitters
    )
      ? (input.secondSplitters ?? input.second_splitters)
      : [],
    clients: Array.isArray(input.clients) ? input.clients : [],
  };
}

function publicUsers(users) {
  return users.map(u => ({
    id: String(u.id),
    username: u.username,
    role: u.role,
    permissions: u.permissions || undefined,
    password: ''
  }));
}

function cleanStateForClient(state) {
  const s = normalizeState(state);
  s.users = publicUsers(s.users);
  return s;
}

function scryptHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;

  if (!stored.startsWith('scrypt$')) {
    const a = Buffer.from(password);
    const b = Buffer.from(stored);

    return (
      a.length === b.length &&
      crypto.timingSafeEqual(a, b)
    );
  }

  const [, salt, hash] = stored.split('$');

  if (!salt || !hash) return false;

  const actual = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(hash, 'hex');

  return (
    a.length === b.length &&
    crypto.timingSafeEqual(a, b)
  );
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function auth(req, res, next) {
  const header = req.get('authorization') || '';

  const token = header.startsWith('Bearer ')
    ? header.slice(7).trim()
    : '';

  const session = sessions.get(token);

  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);

    return res.status(401).json({
      ok: false,
      error: 'Unauthorized'
    });
  }

  session.expiresAt = Date.now() + SESSION_MS;

  req.user = session.user;
  req.token = token;

  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        ok: false,
        error: 'Permission denied'
      });
    }

    next();
  };
}

async function tableExists(client, table) {
  const r = await client.query(
    `
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema='public'
      AND table_name=$1
    ) AS exists
    `,
    [table]
  );

  return r.rows[0].exists;
}

async function ensureSchema() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS public.carnival_state (
        id INTEGER PRIMARY KEY,
        users JSONB NOT NULL DEFAULT '[]'::jsonb,
        zones JSONB NOT NULL DEFAULT '[]'::jsonb,
        pops JSONB NOT NULL DEFAULT '[]'::jsonb,
        olts JSONB NOT NULL DEFAULT '[]'::jsonb,
        ports JSONB NOT NULL DEFAULT '[]'::jsonb,
        first_splitters JSONB NOT NULL DEFAULT '[]'::jsonb,
        second_splitters JSONB NOT NULL DEFAULT '[]'::jsonb,
        clients JSONB NOT NULL DEFAULT '[]'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS public.app_users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'read',
        password_hash TEXT NOT NULL,
        permissions JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const columns = [
      ['users', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['zones', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['pops', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['olts', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['ports', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      [
        'first_splitters',
        "JSONB NOT NULL DEFAULT '[]'::jsonb"
      ],
      [
        'second_splitters',
        "JSONB NOT NULL DEFAULT '[]'::jsonb"
      ],
      ['clients', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['updated_at', 'TIMESTAMPTZ NOT NULL DEFAULT NOW()'],
    ];

    for (const [name, type] of columns) {
      await client.query(
        `ALTER TABLE public.carnival_state
         ADD COLUMN IF NOT EXISTS ${name} ${type}`
      );
    }

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

function stateFromRow(row) {
  if (!row) return emptyState();

  return normalizeState({
    users: row.users,
    zones: row.zones,
    pops: row.pops,
    olts: row.olts,
    ports: row.ports,
    firstSplitters: row.first_splitters,
    secondSplitters: row.second_splitters,
    clients: row.clients
  });
}

async function readState() {
  const r = await pool.query(
    'SELECT * FROM public.carnival_state WHERE id=1'
  );

  return stateFromRow(r.rows[0]);
}

async function writeState(state) {
  const s = normalizeState(state);

  await pool.query(
    `
    INSERT INTO public.carnival_state
      (
        id,
        users,
        zones,
        pops,
        olts,
        ports,
        first_splitters,
        second_splitters,
        clients,
        updated_at
      )
    VALUES
      (
        1,
        $1::jsonb,
        $2::jsonb,
        $3::jsonb,
        $4::jsonb,
        $5::jsonb,
        $6::jsonb,
        $7::jsonb,
        $8::jsonb,
        NOW()
      )
    ON CONFLICT (id)
    DO UPDATE SET
      users=EXCLUDED.users,
      zones=EXCLUDED.zones,
      pops=EXCLUDED.pops,
      olts=EXCLUDED.olts,
      ports=EXCLUDED.ports,
      first_splitters=EXCLUDED.first_splitters,
      second_splitters=EXCLUDED.second_splitters,
      clients=EXCLUDED.clients,
      updated_at=NOW()
    `,
    [
      JSON.stringify(s.users),
      JSON.stringify(s.zones),
      JSON.stringify(s.pops),
      JSON.stringify(s.olts),
      JSON.stringify(s.ports),
      JSON.stringify(s.firstSplitters),
      JSON.stringify(s.secondSplitters),
      JSON.stringify(s.clients)
    ]
  );
}

/*
  IMPORTANT PASSWORD FIX:

  Existing users are NOT silently changed on every deploy.

  To reset the bootstrap passwords once:
    RESET_BOOTSTRAP_PASSWORDS=true

  After login works, remove that variable or set it to false.
*/

async function bootstrapUsers() {
  const defaults = [
    {
      id: 'u1',
      username: 'admin',
      role: 'admin',
      env: 'BOOTSTRAP_ADMIN_PASSWORD',
      fallback: 'admin123'
    },
    {
      id: 'u2',
      username: 'manager',
      role: 'manager',
      env: 'BOOTSTRAP_MANAGER_PASSWORD',
      fallback: 'manager123'
    },
    {
      id: 'u3',
      username: 'installer',
      role: 'installer',
      env: 'BOOTSTRAP_INSTALLER_PASSWORD',
      fallback: 'installer123'
    },
    {
      id: 'u4',
      username: 'viewer',
      role: 'viewer',
      env: 'BOOTSTRAP_VIEWER_PASSWORD',
      fallback: 'viewer123'
    }
  ];

  const resetPasswords =
    String(
      process.env.RESET_BOOTSTRAP_PASSWORDS || ''
    ).toLowerCase() === 'true';

  await pool.query(
    `
    UPDATE public.app_users
    SET role='installer', updated_at=NOW()
    WHERE role='write'
    `
  );

  await pool.query(
    `
    UPDATE public.app_users
    SET role='viewer', updated_at=NOW()
    WHERE role='read'
    `
  );

  for (const u of defaults) {
    const existing = await pool.query(
      `
      SELECT id
      FROM public.app_users
      WHERE lower(username)=lower($1)
      LIMIT 1
      `,
      [u.username]
    );

    const password =
      process.env[u.env] || u.fallback;

    if (existing.rowCount) {
      if (resetPasswords) {
        await pool.query(
          `
          UPDATE public.app_users
          SET
            role=$1,
            password_hash=$2,
            updated_at=NOW()
          WHERE id=$3
          `,
          [
            u.role,
            scryptHash(password),
            existing.rows[0].id
          ]
        );

        console.log(
          `Bootstrap password reset for ${u.username}`
        );
      }
    } else {
      await pool.query(
        `
        INSERT INTO public.app_users
          (id, username, role, password_hash)
        VALUES
          ($1, $2, $3, $4)
        `,
        [
          u.id,
          u.username,
          u.role,
          scryptHash(password)
        ]
      );

      console.log(
        `Bootstrap user created: ${u.username}`
      );
    }
  }

  const users = await pool.query(
    `
    SELECT id, username, role, permissions
    FROM public.app_users
    ORDER BY username
    `
  );

  const state = await readState();

  state.users = users.rows.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    ...(u.permissions
      ? { permissions: u.permissions }
      : {})
  }));

  await writeState(state);
}

async function importLegacyTablesIfStateEmpty() {
  const current = await readState();

  const hasData =
    TABLE_KEYS.some(
      k => current[k].length
    ) ||
    current.users.length;

  if (hasData) return current;

  const client = await pool.connect();

  try {
    const result = emptyState();

    const mappings = [
      ['zones', 'zones'],
      ['pops', 'pops'],
      ['olts', 'olts'],
      ['ports', 'ports'],
      ['first_splitters', 'firstSplitters'],
      ['second_splitters', 'secondSplitters'],
      ['clients', 'clients']
    ];

    for (const [table, key] of mappings) {
      if (!(await tableExists(client, table))) {
        continue;
      }

      try {
        const r = await client.query(
          `SELECT * FROM public.${table}`
        );

        result[key] = r.rows.map(row => {
          if (
            row.data !== undefined &&
            row.data !== null
          ) {
            try {
              return typeof row.data === 'string'
                ? JSON.parse(row.data)
                : row.data;
            } catch {}
          }

          const copy = { ...row };

          delete copy.created_at;
          delete copy.updated_at;

          if (copy.id !== undefined) {
            copy.id = String(copy.id);
          }

          return copy;
        });
      } catch (e) {
        console.warn(
          `Legacy table import skipped for ${table}: ${e.message}`
        );
      }
    }

    if (
      result.zones.length ||
      result.pops.length ||
      result.olts.length ||
      result.ports.length ||
      result.firstSplitters.length ||
      result.secondSplitters.length ||
      result.clients.length
    ) {
      await writeState(result);
    }

    return result;
  } finally {
    client.release();
  }
}
