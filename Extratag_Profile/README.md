# ExtraTag – secure profile signup (Node.js, no npm packages needed)

Requires Node 22.13 or newer (uses the built-in node:sqlite and crypto.scrypt).

## Run locally (Windows cmd)
    set PATH=D:\nodejs;%PATH%
    set EXTRATAG_DEV=1
    node server.js
Open http://127.0.0.1:5000 - in DEV mode the 6-digit verification code is printed in this window.

## Production
Copy `.env.example` to `.env`, fill it in (SMTP needs `npm install nodemailer`), do NOT set EXTRATAG_DEV,
and put Caddy/nginx with HTTPS in front (cookies are Secure + __Host- prefixed). Set TRUSTED_PROXIES=1 behind one proxy.

For @extra-tag.com mailbox creation you must set `MIGADU_TOKEN` (the API token).
`MIGADU_USER` defaults to `merchavido@gmail.com` (same as main.py create_exmail()).

## Mailbox creation (mirrors main.py)
- `local_part` = the user's username
- password = `P@ssword123!` (constant, same as the desktop app)
- the password is shown once in the UI and stored in GitHub `global_history.json` as `expass`
- Migadu statuses 200 / 201 / 400 / 409 are all treated as success (main.py behaviour)

## Security
- scrypt (N=65536) password hashes; no minimum length (1..128) as requested
- generic login errors, dummy hash for unknown users, per-IP + per-account rate limits, 15-min lockout after 5 failures
- no email enumeration on signup; single-use 24h hashed 6-digit verification codes
- server-side sessions (random token, only its hash stored), HttpOnly/Secure/SameSite=Strict, rotated on login,
  30 min idle / 7 day max, other devices signed out on password change
- CSRF token + Origin check + JSON-only; strict CSP, HSTS, nosniff, no framing; parameterised SQL; no innerHTML

## Not included yet
2FA (TOTP/passkeys), forgot-password, CAPTCHA, account deletion, DB backups.

## Import accounts from the desktop app (global_history.json)
    node server.js import
    node server.js import C:\path\global_history.json
Passwords are hashed during import and never printed; imported accounts are marked verified. Safe to run again (existing emails are skipped).