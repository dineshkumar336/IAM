# IAM Dashboard

A small Identity & Access Management service with a web console, built with **FastAPI + SQLAlchemy + vanilla JS**.

## Features

| Area | What it does |
|---|---|
| Authentication | Argon2id password hashing, password policy, account lockout (5 failures, 15 min) |
| MFA | TOTP (Google/Microsoft Authenticator) with a **QR code** and a **confirm-code step**; MFA is mandatory and enforced on the server |
| Sessions | Short-lived JWTs (30 min), pinned `HS256`, instant revocation through a per-user `token_version` |
| Authorization | Role-based access control (`Admin`, `User`), checked against the database on every request |
| Administration | Change roles, disable/enable, unlock, reset MFA, delete users, with last-admin protection |
| Console | Teal, green and red UI with light animations, shows your last sign-in, live session time and MFA state |
| Audit | Every security event is logged with actor, target, IP and user agent in a **hash-chained, tamper-evident** log with paging and an integrity check |

## Project structure

```
app/
  main.py          app factory, routers, static files
  config.py        settings from environment (.env)
  database.py      engine / session
  models.py        Role, User, AuditLog
  schemas.py       request models
  security.py      Argon2, JWT, TOTP, QR code
  audit.py         hash-chained audit log + verification
  deps.py          auth dependencies, scopes, RBAC
  routers/         auth.py  mfa.py  user.py  admin.py
scripts/
  init_env.py      generates .env with a random JWT secret
  create_admin.py  creates / promotes the first administrator
static/            index.html  app.js  style.css  logo.svg  favicon.svg
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m scripts.init_env          # creates .env with a random JWT_SECRET
python -m scripts.create_admin      # asks for the first admin's username and password

uvicorn app.main:app --reload       # open http://127.0.0.1:8000
```

> **Upgrading from the old version?** The database schema changed. Delete the old `iam_tool.db` first.

The app **refuses to start** without `JWT_SECRET` (32+ characters). Never commit `.env`.

### First login
1. Log in with the admin account. You are sent to MFA enrolment (this is enforced by the server, not just the page).
2. Scan the QR code, enter the 6-digit code, and you get a full session.
3. Other people can **Create account** (always a standard `User`). An admin can promote them in the **Users** tab.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET` | required | signing key, 32+ chars |
| `DATABASE_URL` | `sqlite:///./iam_tool.db` | any SQLAlchemy URL |
| `ACCESS_TOKEN_MINUTES` | 30 | session lifetime |
| `MAX_FAILED_ATTEMPTS` / `LOCKOUT_MINUTES` | 5 / 15 | lockout policy |
| `TOTP_ISSUER` | IAM Dashboard | name shown in the authenticator app |

## API

| Method & path | Access | Purpose |
|---|---|---|
| `POST /register` | public | create a standard user (no role field) |
| `POST /login` | public | form fields `username`, `password`, optional `totp_code` |
| `GET /api/me` | any valid token | username, role, MFA state, scope, session expiry |
| `POST /api/mfa/setup` | limited or full token | create a pending TOTP secret + QR |
| `POST /api/mfa/enable` | limited token | confirm a code, returns a full token |
| `GET /api/user-data`, `/api/admin-data` | User/Admin, Admin | RBAC demo endpoints |
| `GET /api/audit-logs?limit=&offset=` | full token | admins see all events, users see their own |
| `GET /api/audit-logs/verify` | Admin | checks the hash chain |
| `GET /api/admin/users` | Admin | list users |
| `PUT /api/admin/users/{id}/role` `/status` `/reset-mfa` `/unlock` | Admin | manage a user |
| `DELETE /api/admin/users/{id}` | Admin | delete a user |

## Security decisions

| Control | Why |
|---|---|
| Role is never read from the client on registration | prevents anyone registering as Admin |
| `JWT_SECRET` only from the environment | no secret in source control |
| The login form shows "N attempts remaining", and unknown or disabled usernames get an identical look-alike counter and lockout (`app/attempts.py`), plus a dummy Argon2 verify | users get feedback, but the messages and timing never reveal which usernames exist |
| Two token scopes: `mfa_setup` (MFA endpoints only) and `full` | MFA cannot be skipped by calling the API directly |
| MFA is enabled only after a valid code is entered | no lock-out from an unsaved secret |
| `token_version` bumped on disable, MFA reset and MFA enrolment | old tokens die immediately |
| Last-admin guard; admins cannot demote, disable, delete or reset MFA on themselves | the system can't be left without an administrator |
| Hash-chained audit log, IP and user agent recorded | editing or deleting a row is detectable |
| UI renders all data with `textContent`, no inline handlers | a hostile username or log entry cannot run script in an admin's browser |
| JWT held in memory, not `localStorage`; algorithm pinned | smaller theft surface, no `alg: none` |

## Known limitations (not implemented yet)

- No per-IP rate limiting, so an attacker can still lock out a known account on purpose
- The look-alike counters for unknown usernames live in memory: they reset on restart and are not shared between workers
- No refresh tokens or logout revocation; tokens live for 30 minutes unless the user is disabled or MFA is reset
- TOTP secrets are stored unencrypted in the database, no backup codes, and used codes are not blocked from replay inside their window
- No `Content-Security-Policy` or other security headers, and no HTTPS (put it behind a TLS proxy)
- The first MFA enrolment trusts whoever knows the password until MFA is enabled
- No automated tests yet
- `Username already registered` on sign-up still reveals which usernames exist
- The audit chain detects edits and deletions in the middle, but not truncation of the newest entries; note the `head` hash from the verify endpoint externally if you need that
