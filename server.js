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
  console.error(
    'DATABASE_URL is missing. Add it in Render Environment Variables.'
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
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

function emptyState() {
  return {
    users: [],
    zones: [],
    pops: [],
    olts: [],
    ports: [],
    firstSplitters: [],
    secondSplitters: [],
    clients: []
  };
}

function normalizeState(input = {}) {
  return {
    users: Array.isArray(input.users)
      ? input.users
      : [],

    zones: Array.isArray(input.zones)
      ? input.zones
      : [],

    pops: Array.isArray(input.pops)
      ? input.pops
      : [],

    olts: Array.isArray(input.olts)
      ? input.olts
      : [],

    ports: Array.isArray(input.ports)
      ? input.ports
      : [],

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

    clients: Array.isArray(input.clients)
      ? input.clients
      : []
  };
}

function publicUsers(users) {
  return users.map((u) => ({
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

/* =========================================================
   PASSWORD
========================================================= */

function scryptHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) {
    return false;
  }

  /*
    Legacy plaintext password support.
  */

  if (!stored.startsWith('scrypt$')) {
    const a = Buffer.from(password);
    const b = Buffer.from(stored);

    return (
      a.length === b.length &&
      crypto.timingSafeEqual(a, b)
    );
  }

  const [, salt, hash] = stored.split('$');

  if (!salt || !hash) {
    return false;
  }

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

/* =========================================================
   SESSION
========================================================= */

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
    if (token) {
      sessions.delete(token);
    }

    return res.status(401).json({
      ok: false,
      error: 'Unauthorized'
    });
  }

  session.expiresAt =
    Date.now() + SESSION_MS;

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

/* =========================================================
   DATABASE HELPERS
========================================================= */

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

/* =========================================================
   DATABASE SCHEMA
========================================================= */

async function ensureSchema() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    /*
      Main application state table.
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS public.carnival_state (
        id INTEGER PRIMARY KEY,

        users JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        zones JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        pops JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        olts JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        ports JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        first_splitters JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        second_splitters JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        clients JSONB NOT NULL
          DEFAULT '[]'::jsonb,

        updated_at TIMESTAMPTZ NOT NULL
          DEFAULT NOW()
      )
    `);

    /*
      Login users.
    */

    await client.query(`
      CREATE TABLE IF NOT EXISTS public.app_users (
        id TEXT PRIMARY KEY,

        username TEXT UNIQUE NOT NULL,

        role TEXT NOT NULL
          DEFAULT 'read',

        password_hash TEXT NOT NULL,

        permissions JSONB,

        created_at TIMESTAMPTZ NOT NULL
          DEFAULT NOW(),

        updated_at TIMESTAMPTZ NOT NULL
          DEFAULT NOW()
      )
    `);

    /*
      Make sure older carnival_state tables
      also get all required columns.
    */

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
      [
        'updated_at',
        'TIMESTAMPTZ NOT NULL DEFAULT NOW()'
      ]
    ];

    for (const [name, type] of columns) {
      await client.query(
        `
        ALTER TABLE public.carnival_state
        ADD COLUMN IF NOT EXISTS ${name} ${type}
        `
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

/* =========================================================
   STATE READ / WRITE
========================================================= */

function stateFromRow(row) {
  if (!row) {
    return emptyState();
  }

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
    `
    SELECT *
    FROM public.carnival_state
    WHERE id=1
    `
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

/* =========================================================
   BOOTSTRAP USERS
========================================================= */

/*
  Creates:
    admin
    installer
    viewer

  Environment variables:

    BOOTSTRAP_ADMIN_PASSWORD
    BOOTSTRAP_INSTALLER_PASSWORD
    BOOTSTRAP_VIEWER_PASSWORD

  IMPORTANT:

  If RESET_BOOTSTRAP_PASSWORDS=true

  existing bootstrap users will also get
  their passwords reset from Render Environment Variables.

  After successful login, remove/disable
  RESET_BOOTSTRAP_PASSWORDS.
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
      username: 'installer',
      role: 'write',
      env: 'BOOTSTRAP_INSTALLER_PASSWORD',
      fallback: 'installer123'
    },

    {
      id: 'u3',
      username: 'viewer',
      role: 'read',
      env: 'BOOTSTRAP_VIEWER_PASSWORD',
      fallback: 'viewer123'
    }
  ];

  const resetPasswords =
    String(
      process.env.RESET_BOOTSTRAP_PASSWORDS || ''
    ).toLowerCase() === 'true';

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

    /*
      Existing user
    */

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

      continue;
    }

    /*
      User does not exist -> create it.
    */

    await pool.query(
      `
      INSERT INTO public.app_users
      (
        id,
        username,
        role,
        password_hash
      )
      VALUES
      (
        $1,
        $2,
        $3,
        $4
      )
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

  /*
    Copy users into application state.
  */

  const users = await pool.query(
    `
    SELECT
      id,
      username,
      role,
      permissions

    FROM public.app_users

    ORDER BY username
    `
  );

  const state = await readState();

  state.users = users.rows.map((u) => ({
    id: u.id,
    username: u.username,
    role: u.role,

    ...(u.permissions
      ? { permissions: u.permissions }
      : {})
  }));

  await writeState(state);
}

/* =========================================================
   LEGACY TABLE IMPORT
========================================================= */

async function importLegacyTablesIfStateEmpty() {
  const current = await readState();

  const hasData =
    TABLE_KEYS.some(
      (k) => current[k].length
    ) ||
    current.users.length;

  if (hasData) {
    return current;
  }

  const client = await pool.connect();

  try {
    const result = emptyState();

    const mappings = [
      ['zones', 'zones'],
      ['pops', 'pops'],
      ['olts', 'olts'],
      ['ports', 'ports'],
      [
        'first_splitters',
        'firstSplitters'
      ],
      [
        'second_splitters',
        'secondSplitters'
      ],
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

        result[key] = r.rows.map((row) => {
          /*
            If old table has JSON data column.
          */

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

          const copy = {
            ...row
          };

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

/* =========================================================
   SYNC APP USERS
========================================================= */

async function syncAppUsersFromState(state) {
  const incoming =
    Array.isArray(state.users)
      ? state.users
      : [];

  const existing = await pool.query(
    `
    SELECT
      id,
      username,
      role,
      password_hash,
      permissions

    FROM public.app_users
    `
  );

  const byId = new Map(
    existing.rows.map((x) => [
      String(x.id),
      x
    ])
  );

  const byUsername = new Map(
    existing.rows.map((x) => [
      x.username.toLowerCase(),
      x
    ])
  );

  const seenIds = new Set();

  for (const raw of incoming) {
    const id = String(
      raw.id || crypto.randomUUID()
    );

    const username = String(
      raw.username || ''
    ).trim();

    if (!username) {
      continue;
    }

    const old =
      byId.get(id) ||
      byUsername.get(
        username.toLowerCase()
      );

    const effectiveId =
      old?.id || id;

    seenIds.add(
      String(effectiveId)
    );

    const role =
      ['admin', 'write', 'read'].includes(
        raw.role
      )
        ? raw.role
        : (old?.role || 'read');

    const permissions =
      raw.permissions ??
      old?.permissions ??
      null;

    let passwordHash =
      old?.password_hash;

    /*
      Only change password if the
      frontend actually sends one.
    */

    if (
      raw.password &&
      String(raw.password).trim()
    ) {
      passwordHash =
        scryptHash(
          String(raw.password)
        );
    }

    /*
      Fallback password for a brand-new user.
    */

    if (!passwordHash) {
      passwordHash =
        scryptHash(
          username + '123'
        );
    }

    if (old) {
      await pool.query(
        `
        UPDATE public.app_users

        SET
          username=$1,
          role=$2,
          password_hash=$3,
          permissions=$4,
          updated_at=NOW()

        WHERE id=$5
        `,
        [
          username,
          role,
          passwordHash,
          permissions
            ? JSON.stringify(permissions)
            : null,
          old.id
        ]
      );
    } else {
      await pool.query(
        `
        INSERT INTO public.app_users
        (
          id,
          username,
          role,
          password_hash,
          permissions
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5
        )

        ON CONFLICT (username)
        DO NOTHING
        `,
        [
          id,
          username,
          role,
          passwordHash,
          permissions
            ? JSON.stringify(permissions)
            : null
        ]
      );
    }
  }

  /*
    Keep admin safe.
  */

  if (seenIds.size) {
    await pool.query(
      `
      DELETE FROM public.app_users

      WHERE username <> 'admin'

      AND id <> ALL($1::text[])
      `,
      [
        Array.from(seenIds)
      ]
    );
  }
}

/* =========================================================
   SYNC FULL STATE
========================================================= */

async function syncState(state, user) {
  const normalized =
    normalizeState(state);

  /*
    Non-admin users cannot modify users.
  */

  if (user.role !== 'admin') {
    const old =
      await readState();

    normalized.users =
      old.users;
  }

  /*
    Save complete state.
  */

  await writeState(normalized);

  /*
    Only admin can sync app users.
  */

  if (user.role === 'admin') {
    await syncAppUsersFromState(
      normalized
    );
  }

  /*
    Read users again from database.
  */

  const users = await pool.query(
    `
    SELECT
      id,
      username,
      role,
      permissions

    FROM public.app_users

    ORDER BY username
    `
  );

  normalized.users =
    users.rows.map((u) => ({
      id: u.id,
      username: u.username,
      role: u.role,

      ...(u.permissions
        ? {
            permissions:
              u.permissions
          }
        : {})
    }));

  /*
    Save state again with latest users.
  */

  await writeState(
    normalized
  );

  return normalized;
}

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  '/api/health',
  async (req, res) => {
    try {
      /*
        Test database.
      */

      const r =
        await pool.query(
          'SELECT 1 AS ok'
        );

      const s =
        await pool.query(
          `
          SELECT updated_at
          FROM public.carnival_state
          WHERE id=1
          `
        );

      res.json({
        ok: true,

        service:
          'carnival-online-supabase',

        database:
          'connected',

        stateUpdatedAt:
          s.rows[0]?.updated_at ||
          null,

        time:
          new Date().toISOString()
      });
    } catch (e) {
      console.error(
        'Health check failed:',
        e
      );

      res.status(500).json({
        ok: false,

        database:
          'disconnected',

        error:
          e.message
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  '/api/login',
  async (req, res) => {
    try {
      const username =
        String(
          req.body?.username || ''
        ).trim();

      const password =
        String(
          req.body?.password || ''
        );

      if (
        !username ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          error:
            'Username and password are required'
        });
      }

      const q =
        await pool.query(
          `
          SELECT
            id,
            username,
            role,
            password_hash,
            permissions

          FROM public.app_users

          WHERE lower(username)
            = lower($1)

          LIMIT 1
          `,
          [username]
        );

      /*
        Username does not exist.
      */

      if (!q.rowCount) {
        return res.status(401).json({
          ok: false,
          error:
            'Invalid credentials'
        });
      }

      const u =
        q.rows[0];

      const valid =
        verifyPassword(
          password,
          u.password_hash
        );

      /*
        Password wrong.
      */

      if (!valid) {
        return res.status(401).json({
          ok: false,
          error:
            'Invalid credentials'
        });
      }

      /*
        Upgrade old plaintext passwords
        to scrypt.
      */

      if (
        !u.password_hash.startsWith(
          'scrypt$'
        )
      ) {
        await pool.query(
          `
          UPDATE public.app_users

          SET
            password_hash=$1,
            updated_at=NOW()

          WHERE id=$2
          `,
          [
            scryptHash(password),
            u.id
          ]
        );
      }

      /*
        Create session token.
      */

      const token =
        newToken();

      sessions.set(
        token,
        {
          user: {
            id: u.id,
            username: u.username,
            role: u.role,

            permissions:
              u.permissions ||
              undefined
          },

          expiresAt:
            Date.now() +
            SESSION_MS
        }
      );

      res.json({
        ok: true,

        token,

        user: {
          id: u.id,
          username: u.username,
          role: u.role,

          permissions:
            u.permissions ||
            undefined
        }
      });
    } catch (e) {
      console.error(
        'Login failed:',
        e
      );

      res.status(500).json({
        ok: false,
        error:
          'Server error during login'
      });
    }
  }
);

/* =========================================================
   GET STATE
========================================================= */

app.get(
  '/api/state',
  auth,
  async (req, res) => {
    try {
      const state =
        await readState();

      /*
        If state has no users,
        rebuild users from app_users.
      */

      if (!state.users.length) {
        const users =
          await pool.query(
            `
            SELECT
              id,
              username,
              role,
              permissions

            FROM public.app_users

            ORDER BY username
            `
          );

        state.users =
          users.rows.map((u) => ({
            id: u.id,
            username: u.username,
            role: u.role,

            ...(u.permissions
              ? {
                  permissions:
                    u.permissions
                }
              : {})
          }));
      }

      res.json(
        cleanStateForClient(
          state
        )
      );
    } catch (e) {
      console.error(
        'State read failed:',
        e
      );

      res.status(500).json({
        ok: false,
        error:
          'Database read failed: ' +
          e.message
      });
    }
  }
);

/* =========================================================
   SAVE STATE
========================================================= */

app.put(
  '/api/state',
  auth,
  requireRole(
    'admin',
    'write'
  ),
  async (req, res) => {
    try {
      const state =
        normalizeState(
          req.body || {}
        );

      const saved =
        await syncState(
          state,
          req.user
        );

      res.json({
        ok: true,

        state:
          cleanStateForClient(
            saved
          )
      });
    } catch (e) {
      console.error(
        'State write failed:',
        e
      );

      res.status(500).json({
        ok: false,
        error:
          'Database write failed: ' +
          e.message
      });
    }
  }
);

/* =========================================================
   MIGRATE
========================================================= */

app.post(
  '/api/migrate',
  auth,
  requireRole('admin'),
  async (req, res) => {
    try {
      const state =
        await importLegacyTablesIfStateEmpty();

      res.json({
        ok: true,

        state:
          cleanStateForClient(
            state
          )
      });
    } catch (e) {
      res.status(500).json({
        ok: false,

        error:
          'Migration failed: ' +
          e.message
      });
    }
  }
);

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
  '/api/change-password',
  auth,
  async (req, res) => {
    try {
      const oldPassword =
        String(
          req.body?.oldPassword || ''
        );

      const newPassword =
        String(
          req.body?.newPassword || ''
        );

      if (
        newPassword.length < 4
      ) {
        return res.status(400).json({
          ok: false,

          error:
            'New password must be at least 4 characters'
        });
      }

      const q =
        await pool.query(
          `
          SELECT password_hash
          FROM public.app_users
          WHERE id=$1
          `,
          [req.user.id]
        );

      if (
        !q.rowCount ||
        !verifyPassword(
          oldPassword,
          q.rows[0].password_hash
        )
      ) {
        return res.status(401).json({
          ok: false,

          error:
            'Current password is incorrect'
        });
      }

      await pool.query(
        `
        UPDATE public.app_users

        SET
          password_hash=$1,
          updated_at=NOW()

        WHERE id=$2
        `,
        [
          scryptHash(
            newPassword
          ),
          req.user.id
        ]
      );

      res.json({
        ok: true
      });
    } catch (e) {
      res.status(500).json({
        ok: false,

        error:
          'Password change failed: ' +
          e.message
      });
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  '/api/logout',
  auth,
  (req, res) => {
    sessions.delete(
      req.token
    );

    res.json({
      ok: true
    });
  }
);

/* =========================================================
   STATIC FRONTEND
========================================================= */

app.use(
  express.static(
    PUBLIC_DIR,
    {
      extensions: ['html']
    }
  )
);

/*
  SPA fallback.
*/

app.get(
  '*',
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        'index.html'
      )
    );
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function start() {
  /*
    Create database tables.
  */

  await ensureSchema();

  /*
    Import old data if necessary.
  */

  await importLegacyTablesIfStateEmpty();

  /*
    Create / reset bootstrap users.
  */

  await bootstrapUsers();

  /*
    Final database connection test.
  */

  await pool.query(
    'SELECT 1'
  );

  /*
    Start Express server.
  */

  app.listen(
    PORT,
    () => {
      console.log(
        `Carnival Internet Online running on port ${PORT}`
      );
    }
  );
}

start().catch(
  (err) => {
    console.error(
      'Startup failed:',
      err
    );

    process.exit(1);
  }
);

/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

setInterval(
  () => {
    const now =
      Date.now();

    for (
      const [
        token,
        session
      ] of sessions
    ) {
      if (
        session.expiresAt <
        now
      ) {
        sessions.delete(
          token
        );
      }
    }
  },
  30 * 60 * 1000
).unref();
