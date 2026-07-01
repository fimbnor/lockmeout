# Locker

Scheduled password vault. You can either lock a password immediately until a future unlock time, or keep it available until a future lock time.

## Setup

```bash
npm install
cp .env.example .env
# edit .env — set MONGO_URI and a long random JWT_SECRET
npm start
```

Open http://localhost:3000

## How it works

- Master password never leaves your browser
- Secrets are encrypted in the browser with a key derived from your master password (PBKDF2 → AES-GCM)
- Unlock-later secrets are additionally wrapped with [drand timelock encryption](https://drand.love/) targeting the unlock time's round
- Lock-later secrets stay as AES-GCM ciphertext and the server stops returning them after the scheduled lock time
- Secrets can also use a weekly lock schedule by choosing days + a daily locked time window, with optional weekly repeat
- Server stores the ciphertext plus either an unlock timestamp or a lock timestamp
- Server refuses to return an unlock-later secret until `unlockAt <= now`, and refuses to return a lock-later secret once `lockAt <= now`
- You can't extend a tlock-encrypted secret server-side; reveal at unlock and re-create with a later unlock time
- You can't delete an unlock-later secret before it unlocks

## Endpoints

- `POST /api/auth/signup` — `{ email, salt, authHash }`
- `POST /api/auth/salt` — `{ email }` → `{ salt }`
- `POST /api/auth/login` — `{ email, authHash }` → `{ token }`
- `POST /api/vault` — either `{ label, ciphertext, drandRound, unlockAt }` / legacy `{ ciphertext, iv, unlockAt }`, `{ label, ciphertext, iv, lockAt }`, or `{ label, ciphertext, iv, weeklyLockSchedule, repeatWeekly, scheduleTimezoneOffsetMinutes }`
- `GET /api/vault` — list (metadata only)
- `GET /api/vault/:id` — returns ciphertext if unlocked, 403 if not
- `PATCH /api/vault/:id/extend` — `{ scheduleAt }` (legacy `{ unlockAt }` still accepted; for lock-later items this reschedules the lock later)
- `DELETE /api/vault/:id` — unlock-later items only after unlock; lock-later items any time

## What this gives you and what it doesn't

It gives you:
- Server can't read your passwords (zero-knowledge: the AES key never leaves your browser).
- Time lock is now cryptographic, not just a server check. Even with full database access and your master password, the outer ciphertext cannot be opened until the drand network publishes the signature for the unlock round. This protects against the developer/operator editing the DB to bypass the lock.

It doesn't give you:
- Protection against a malicious server pushing modified client JS that exfiltrates your master password the next time you log in. Removing this requires distributing the client as a signed/reproducible artifact (browser extension or native app) instead of HTML served by this server.
- Protection against drand being permanently down (locked items would never unlock). drand mainnet has run continuously since 2020 with multiple independent operators, but it is an external dependency.
