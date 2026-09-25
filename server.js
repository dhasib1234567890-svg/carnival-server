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

const SESSION_MS = 12 * 60 * 60 * 1000;
const SESSION_CLEANUP_MS = 30 * 60 * 1000;
const TABLE_KEYS = ['zones', 'pops', 'olts', 'ports', 'firstSplitters', 'secondSplitters', 'clients'];

const emptyState = () => ({
  users: [], zones: [], pops: [], olts: [], ports: [],
  firstSplitters: [], secondSplitters: [], clients: []
});

function normalizeState(input = {}) {
  return {
    users: Array.isArray(input.users) ? input.users : [],
    zones: Array.isArray(input.zones) ? input.zones : [],
    pops: Array.isArray(input.pops) ? input.pops : [],
    olts: Array.isArray(input.olts) ? input.olts : [],
    ports: Array.isArray(input.ports) ? input.ports : [],
    firstSplitters: Array.isArray(input.firstSplitters ?? input.first_splitters) ? (input.firstSplitters ?? input.first_splitters) : [],
    secondSplitters: Array.isArray(input.secondSplitters ?? input.second_splitters) ? (input.secondSplitters ?? input.second_splitters) : [],
    clients: Array.isArray(input.clients) ? input.clients : [],
  };
}

function publicUsers(users) {
  return users.map(u => ({
    id: String(u.id), username: u.username, role: u.role,
    permissions: u.permissions || undefined, password: ''
  }));
}

function cleanStateForClient(state) {
  const s = normalizeState(state);
  s.users = publicUsers(s.users);
  return s;
}

function scryptHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  if (!stored.startsWith('scrypt$')) {
    const a = Buffer.from(password); const b = Buffer.from(stored);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  const [, salt, hash] = stored.split('$');
  if (!salt || !hash) return false;
  const actual = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex'); const b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function newToken() { return crypto.randomBytes(32).toString('hex'); }

function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

async function auth(req, res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!token) return res.status(401).json({ ok: false, error: 'Unauthorized' });

  try {
    const hash = tokenHash(token);
    const q = await pool.query(`
      SELECT s.token_hash, s.expires_at, u.id, u.username, u.role, u.permissions
      FROM public.app_sessions s
      JOIN public.app_users u ON u.id = s.user_id
      WHERE s.token_hash=$1 AND s.expires_at > NOW()
      LIMIT 1
    `, [hash]);
    if (!q.rowCount) return res.status(401).json({ ok: false, error: 'Unauthorized' });

    const row = q.rows[0];
    const user = { id: row.id, username: row.username, role: row.role, permissions: row.permissions || undefined };
    await pool.query('UPDATE public.app_sessions SET expires_at=NOW()+($1 * INTERVAL '1 millisecond'), updated_at=NOW() WHERE token_hash=$2', [SESSION_MS, hash]);
    req.user = user;
    req.token = token;
    next();
  } catch (e) {
    console.error('Auth lookup failed:', e);
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ ok: false, error: 'Permission denied' });
    next();
  };
}

async function tableExists(client, table) {
  const r = await client.query(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1) AS exists`, [table]);
  return r.rows[0].exists;
}

async function ensureSchema() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`CREATE TABLE IF NOT EXISTS public.carnival_state (
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
    )`);
    await client.query(`CREATE TABLE IF NOT EXISTS public.app_users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL DEFAULT 'read',
      password_hash TEXT NOT NULL,
      permissions JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await client.query(`CREATE TABLE IF NOT EXISTS public.app_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_app_sessions_expires_at ON public.app_sessions(expires_at)`);
    const columns = [
      ['users', "JSONB NOT NULL DEFAULT '[]'::jsonb"], ['zones', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['pops', "JSONB NOT NULL DEFAULT '[]'::jsonb"], ['olts', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['ports', "JSONB NOT NULL DEFAULT '[]'::jsonb"], ['first_splitters', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['second_splitters', "JSONB NOT NULL DEFAULT '[]'::jsonb"], ['clients', "JSONB NOT NULL DEFAULT '[]'::jsonb"],
      ['updated_at', 'TIMESTAMPTZ NOT NULL DEFAULT NOW()'],
    ];
    for (const [name, type] of columns) await client.query(`ALTER TABLE public.carnival_state ADD COLUMN IF NOT EXISTS ${name} ${type}`);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}

function stateFromRow(row) {
  if (!row) return emptyState();
  return normalizeState({ users: row.users, zones: row.zones, pops: row.pops, olts: row.olts,
    ports: row.ports, firstSplitters: row.first_splitters, secondSplitters: row.second_splitters, clients: row.clients });
}

async function readState() {
  const r = await pool.query('SELECT * FROM public.carnival_state WHERE id=1');
  return stateFromRow(r.rows[0]);
}

async function writeState(state) {
  const s = normalizeState(state);
  await pool.query(`INSERT INTO public.carnival_state
    (id, users, zones, pops, olts, ports, first_splitters, second_splitters, clients, updated_at)
    VALUES (1,$1::jsonb,$2::jsonb,$3::jsonb,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb,NOW())
    ON CONFLICT (id) DO UPDATE SET users=EXCLUDED.users,zones=EXCLUDED.zones,pops=EXCLUDED.pops,
    olts=EXCLUDED.olts,ports=EXCLUDED.ports,first_splitters=EXCLUDED.first_splitters,
    second_splitters=EXCLUDED.second_splitters,clients=EXCLUDED.clients,updated_at=NOW()`,
    [JSON.stringify(s.users), JSON.stringify(s.zones), JSON.stringify(s.pops), JSON.stringify(s.olts),
     JSON.stringify(s.ports), JSON.stringify(s.firstSplitters), JSON.stringify(s.secondSplitters), JSON.stringify(s.clients)]);
}

/*
  IMPORTANT PASSWORD FIX:
  Existing users are NOT silently changed on every deploy.
  To reset the three bootstrap passwords once, set
  RESET_BOOTSTRAP_PASSWORDS=true in Render and deploy/restart.
  Then set it back to false (or remove it) after login works.
*/
async function bootstrapUsers() {
  const defaults = [
    { id: 'u1', username: 'admin', role: 'admin', env: 'BOOTSTRAP_ADMIN_PASSWORD', fallback: 'admin123' },
    { id: 'u2', username: 'installer', role: 'write', env: 'BOOTSTRAP_INSTALLER_PASSWORD', fallback: 'installer123' },
    { id: 'u3', username: 'viewer', role: 'read', env: 'BOOTSTRAP_VIEWER_PASSWORD', fallback: 'viewer123' },
  ];

  const resetPasswords = String(process.env.RESET_BOOTSTRAP_PASSWORDS || '').toLowerCase() === 'true';

  for (const u of defaults) {
    const existing = await pool.query('SELECT id FROM public.app_users WHERE lower(username)=lower($1) LIMIT 1', [u.username]);
    const password = process.env[u.env] || u.fallback;

    if (existing.rowCount) {
      if (resetPasswords) {
        await pool.query(`UPDATE public.app_users SET role=$1,password_hash=$2,updated_at=NOW() WHERE id=$3`,
          [u.role, scryptHash(password), existing.rows[0].id]);
        console.log(`Bootstrap password reset for ${u.username}`);
      }
    } else {
      await pool.query(`INSERT INTO public.app_users (id,username,role,password_hash) VALUES ($1,$2,$3,$4)`,
        [u.id, u.username, u.role, scryptHash(password)]);
      console.log(`Bootstrap user created: ${u.username}`);
    }
  }

  const users = await pool.query('SELECT id,username,role,permissions FROM public.app_users ORDER BY username');
  const state = await readState();
  state.users = users.rows.map(u => ({ id:u.id, username:u.username, role:u.role, ...(u.permissions ? {permissions:u.permissions} : {}) }));
  await writeState(state);
}

async function importLegacyTablesIfStateEmpty() {
  const current = await readState();
  const hasData = TABLE_KEYS.some(k => current[k].length) || current.users.length;
  if (hasData) return current;

  const client = await pool.connect();
  try {
    const result = emptyState();
    const mappings = [['zones','zones'],['pops','pops'],['olts','olts'],['ports','ports'],['first_splitters','firstSplitters'],['second_splitters','secondSplitters'],['clients','clients']];
    for (const [table,key] of mappings) {
      if (!(await tableExists(client, table))) continue;
      try {
        const r = await client.query(`SELECT * FROM public.${table}`);
        result[key] = r.rows.map(row => {
          if (row.data !== undefined && row.data !== null) {
            try { return typeof row.data === 'string' ? JSON.parse(row.data) : row.data; } catch {}
          }
          const copy = { ...row }; delete copy.created_at; delete copy.updated_at;
          if (copy.id !== undefined) copy.id = String(copy.id);
          return copy;
        });
      } catch (e) { console.warn(`Legacy table import skipped for ${table}: ${e.message}`); }
    }
    if (result.zones.length || result.pops.length || result.olts.length || result.ports.length || result.firstSplitters.length || result.secondSplitters.length || result.clients.length) await writeState(result);
    return result;
  } finally { client.release(); }
}

async function syncAppUsersFromState(state) {
  const incoming = Array.isArray(state.users) ? state.users : [];
  const existing = await pool.query('SELECT id,username,role,password_hash,permissions FROM public.app_users');
  const byId = new Map(existing.rows.map(x => [String(x.id), x]));
  const byUsername = new Map(existing.rows.map(x => [x.username.toLowerCase(), x]));
  const seenIds = new Set();

  for (const raw of incoming) {
    const id = String(raw.id || crypto.randomUUID());
    const username = String(raw.username || '').trim();
    if (!username) continue;
    const old = byId.get(id) || byUsername.get(username.toLowerCase());
    const effectiveId = old?.id || id;
    seenIds.add(String(effectiveId));
    const role = ['admin','write','read'].includes(raw.role) ? raw.role : (old?.role || 'read');
    const permissions = raw.permissions ?? old?.permissions ?? null;
    let passwordHash = old?.password_hash;
    if (raw.password && String(raw.password).trim()) passwordHash = scryptHash(String(raw.password));
    if (!passwordHash) passwordHash = scryptHash(username + '123');

    if (old) {
      await pool.query(`UPDATE public.app_users SET username=$1,role=$2,password_hash=$3,permissions=$4,updated_at=NOW() WHERE id=$5`,
        [username,role,passwordHash,permissions ? JSON.stringify(permissions) : null,old.id]);
    } else {
      await pool.query(`INSERT INTO public.app_users (id,username,role,password_hash,permissions) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (username) DO NOTHING`,
        [id,username,role,passwordHash,permissions ? JSON.stringify(permissions) : null]);
    }
  }
  if (seenIds.size) await pool.query(`DELETE FROM public.app_users WHERE username <> 'admin' AND id <> ALL($1::text[])`, [Array.from(seenIds)]);
}


async function syncLegacyTable(table, key, items, client) {
  if (!(await tableExists(client, table))) return;

  // The legacy tables in this project use an id + data JSONB shape.
  // If a table has a data column, keep the complete app object there.
  // This also works with older rows that were created before carnival_state.
  const cols = await client.query(`
    SELECT column_name, data_type, udt_name, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name=$1
    ORDER BY ordinal_position
  `, [table]);
  const names = new Set(cols.rows.map(r => r.column_name));
  if (!names.has('id')) return;

  // Delete rows that no longer exist in the application state so the
  // normalized tables stay an exact mirror of carnival_state.
  if (!items.length) {
    await client.query(`DELETE FROM public.${table}`);
    return;
  }

  if (names.has('data')) {
    for (const item of items) {
      const id = String(item?.id ?? '');
      if (!id) continue;
      await client.query(
        `INSERT INTO public.${table} (id,data) VALUES ($1,$2::jsonb)
         ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data`,
        [id, JSON.stringify(item)]
      );
    }
    const ids = items.map(x => String(x?.id ?? '')).filter(Boolean);
    await client.query(`DELETE FROM public.${table} WHERE id <> ALL($1::text[])`, [ids]);
    return;
  }

  // Fallback for normalized tables that expose named columns instead of data.
  // Only columns that actually exist are written; unknown app fields are ignored.
  for (const item of items) {
    const id = String(item?.id ?? '');
    if (!id) continue;
    const writable = cols.rows.filter(c =>
      c.column_name !== 'id' &&
      c.column_name !== 'created_at' &&
      c.column_name !== 'updated_at' &&
      Object.prototype.hasOwnProperty.call(item, c.column_name)
    );
    const fields = ['id'];
    const values = [id];
    const placeholders = ['$1'];
    let n = 2;
    for (const c of writable) {
      fields.push(c.column_name);
      let value = item[c.column_name];
      if (c.udt_name === 'jsonb' || c.udt_name === 'json') value = JSON.stringify(value ?? null);
      values.push(value);
      placeholders.push(`$${n++}` + (c.udt_name === 'jsonb' ? '::jsonb' : c.udt_name === 'json' ? '::json' : ''));
    }
    const updates = fields.slice(1).map(f => `${f}=EXCLUDED.${f}`);
    if (updates.length) {
      await client.query(
        `INSERT INTO public.${table} (${fields.join(',')}) VALUES (${placeholders.join(',')})
         ON CONFLICT (id) DO UPDATE SET ${updates.join(',')}`,
        values
      );
    } else {
      await client.query(`INSERT INTO public.${table} (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, [id]);
    }
  }
  const ids = items.map(x => String(x?.id ?? '')).filter(Boolean);
  await client.query(`DELETE FROM public.${table} WHERE id <> ALL($1::text[])`, [ids]);
}

async function syncNormalizedTables(state) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const mappings = [
      ['zones','zones'],
      ['pops','pops'],
      ['olts','olts'],
      ['ports','ports'],
      ['first_splitters','firstSplitters'],
      ['second_splitters','secondSplitters'],
      ['clients','clients'],
    ];
    for (const [table,key] of mappings) {
      await syncLegacyTable(table, key, Array.isArray(state[key]) ? state[key] : [], client);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function syncState(state, user) {
  const normalized = normalizeState(state);
  if (user.role !== 'admin') { const old = await readState(); normalized.users = old.users; }
  await writeState(normalized);
  await syncNormalizedTables(normalized);
  if (user.role === 'admin') await syncAppUsersFromState(normalized);
  const users = await pool.query('SELECT id,username,role,permissions FROM public.app_users ORDER BY username');
  normalized.users = users.rows.map(u => ({ id:u.id,username:u.username,role:u.role, ...(u.permissions ? {permissions:u.permissions} : {}) }));
  await writeState(normalized);
  return normalized;
}

app.get('/api/health', async (req,res) => {
  try {
    await pool.query('SELECT 1 AS ok');
    const s = await pool.query('SELECT updated_at FROM public.carnival_state WHERE id=1');
    res.json({ ok:true, service:'carnival-online-supabase', database:'connected', stateUpdatedAt:s.rows[0]?.updated_at || null, time:new Date().toISOString() });
  } catch (e) {
    console.error('Health check failed:',e);
    res.status(500).json({ ok:false,database:'disconnected',error:e.message });
  }
});

app.post('/api/login', async (req,res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    if (!username || !password) return res.status(400).json({ok:false,error:'Username and password are required'});

    const q = await pool.query(`SELECT id,username,role,password_hash,permissions FROM public.app_users WHERE lower(username)=lower($1) LIMIT 1`, [username]);
    if (!q.rowCount) return res.status(401).json({ok:false,error:'Invalid credentials'});
    const u = q.rows[0];
    if (!verifyPassword(password,u.password_hash)) return res.status(401).json({ok:false,error:'Invalid credentials'});

    if (!u.password_hash.startsWith('scrypt$')) {
      await pool.query('UPDATE public.app_users SET password_hash=$1,updated_at=NOW() WHERE id=$2',[scryptHash(password),u.id]);
    }

    const token = newToken();
    const user = {id:u.id,username:u.username,role:u.role,permissions:u.permissions || undefined};
    await pool.query(`
      INSERT INTO public.app_sessions (token_hash,user_id,expires_at)
      VALUES ($1,$2,NOW()+($3 * INTERVAL '1 millisecond'))
    `, [tokenHash(token), u.id, SESSION_MS]);
    res.json({ok:true,token,user});
  } catch (e) {
    console.error('Login failed:',e);
    res.status(500).json({ok:false,error:'Server error during login'});
  }
});

app.get('/api/state',auth,async (req,res) => {
  try {
    const state = await readState();
    if (!state.users.length) {
      const users = await pool.query('SELECT id,username,role,permissions FROM public.app_users ORDER BY username');
      state.users = users.rows.map(u => ({id:u.id,username:u.username,role:u.role,...(u.permissions ? {permissions:u.permissions}: {})}));
    }
    res.json(cleanStateForClient(state));
  } catch (e) {
    console.error('State read failed:',e);
    res.status(500).json({ok:false,error:'Database read failed: '+e.message});
  }
});

app.put('/api/state',auth,requireRole('admin','write'),async (req,res) => {
  try {
    const state = normalizeState(req.body || {});
    const saved = await syncState(state,req.user);
    res.json({ok:true,state:cleanStateForClient(saved)});
  } catch (e) {
    console.error('State write failed:',e);
    res.status(500).json({ok:false,error:'Database write failed: '+e.message});
  }
});

app.post('/api/migrate',auth,requireRole('admin'),async (req,res) => {
  try {
    const state = await importLegacyTablesIfStateEmpty();
    res.json({ok:true,state:cleanStateForClient(state)});
  } catch (e) {
    res.status(500).json({ok:false,error:'Migration failed: '+e.message});
  }
});

app.post('/api/change-password',auth,async (req,res) => {
  try {
    const oldPassword = String(req.body?.oldPassword || '');
    const newPassword = String(req.body?.newPassword || '');
    if (newPassword.length < 4) return res.status(400).json({ok:false,error:'New password must be at least 4 characters'});
    const q = await pool.query('SELECT password_hash FROM public.app_users WHERE id=$1',[req.user.id]);
    if (!q.rowCount || !verifyPassword(oldPassword,q.rows[0].password_hash)) return res.status(401).json({ok:false,error:'Current password is incorrect'});
    await pool.query('UPDATE public.app_users SET password_hash=$1,updated_at=NOW() WHERE id=$2',[scryptHash(newPassword),req.user.id]);
    res.json({ok:true});
  } catch (e) { res.status(500).json({ok:false,error:'Password change failed: '+e.message}); }
});

app.post('/api/logout',auth,async (req,res) => { try { await pool.query('DELETE FROM public.app_sessions WHERE token_hash=$1',[tokenHash(req.token)]); res.json({ok:true}); } catch (e) { res.status(500).json({ok:false,error:'Logout failed'}); } });

app.use(express.static(PUBLIC_DIR,{extensions:['html']}));
app.get('*',(req,res) => res.sendFile(path.join(PUBLIC_DIR,'index.html')));

async function start() {
  await ensureSchema();
  await importLegacyTablesIfStateEmpty();
  await bootstrapUsers();
  await pool.query('DELETE FROM public.app_sessions WHERE expires_at <= NOW()');
  await pool.query('SELECT 1');
  app.listen(PORT,() => console.log(`Carnival Internet Online running on port ${PORT}`));
}

start().catch(err => { console.error('Startup failed:',err); process.exit(1); });

setInterval(async () => {
  try { await pool.query('DELETE FROM public.app_sessions WHERE expires_at <= NOW()'); }
  catch (e) { console.warn('Session cleanup failed:', e.message); }
}, SESSION_CLEANUP_MS).unref();
