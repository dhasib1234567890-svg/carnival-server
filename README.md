# Carnival Internet Online — Ready for Render

This package uses one persistent flow:

**Browser (`public/index.html`) → Render `server.js` → Supabase PostgreSQL (`DATABASE_URL`)**

The frontend does not contain a Supabase database key/URL and does not write directly to Supabase. Login and Zone/POP/OLT/Port/Splitter/Client state use the backend API.

## Files

- `server.js` — Express backend + PostgreSQL connection + authentication + state API
- `package.json` — Render start configuration
- `public/index.html` — Carnival web app

## Render environment variables

Set these in the Render service:

- `DATABASE_URL` = your Supabase PostgreSQL connection string
- Optional: `BOOTSTRAP_ADMIN_PASSWORD`
- Optional: `BOOTSTRAP_INSTALLER_PASSWORD`
- Optional: `BOOTSTRAP_VIEWER_PASSWORD`

If the three optional passwords are not set, the initial accounts are:

- `admin` / `admin123`
- `installer` / `installer123`
- `viewer` / `viewer123`

Change the passwords after the first successful login.

## Render settings

- Runtime: Node
- Build command: `npm install` (or leave the build command empty if your Render setup already installs dependencies)
- Start command: `npm start`
- Node: `>=20`

## Database

On first startup the backend creates `public.carnival_state` and `public.app_users` if they do not exist. If an older `carnival_state` or old individual tables already contain data, the server attempts a one-time import when the new state is empty.

Check database connectivity at:

`/api/health`

A successful response contains `"ok": true` and `"database": "connected"`.
