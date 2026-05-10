# Locker

Time-locked password vault. You store a password, set an unlock time, and you can't read it back until that time has passed.

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
- Server stores ciphertext + the unlock timestamp
- Server refuses to return the ciphertext until `unlockAt <= now`
- You can extend a lock but never shorten it
- You can't delete a locked secret

## Endpoints

- `POST /api/auth/signup` — `{ email, salt, authHash }`
- `POST /api/auth/salt` — `{ email }` → `{ salt }`
- `POST /api/auth/login` — `{ email, authHash }` → `{ token }`
- `POST /api/vault` — `{ label, ciphertext, iv, unlockAt }`
- `GET /api/vault` — list (metadata only)
- `GET /api/vault/:id` — returns ciphertext if unlocked, 403 if not
- `PATCH /api/vault/:id/extend` — `{ unlockAt }` (must be later)
- `DELETE /api/vault/:id` — only if unlocked

## What this gives you and what it doesn't

It gives you: server can't read your passwords, time lock enforced server-side, can't shorten or delete locked secrets through the API.

It doesn't give you: protection against you the developer editing the database directly. That requires either tlock (drand timelock encryption) or moving the lock state to a chain/external service. Add that later if you need it.
