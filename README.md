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
- The AES-GCM ciphertext is then wrapped with [drand timelock encryption](https://drand.love/) targeting the unlock time's round
- Server stores the wrapped ciphertext, the drand round number, and the unlock timestamp
- Server refuses to return the ciphertext until `unlockAt <= now` (a UX gate; the cryptographic gate is the drand round)
- You can't extend a tlock-encrypted secret server-side; reveal at unlock and re-create with a later unlock time
- You can't delete a locked secret

## Endpoints

- `POST /api/auth/signup` — `{ email, salt, authHash }`
- `POST /api/auth/salt` — `{ email }` → `{ salt }`
- `POST /api/auth/login` — `{ email, authHash }` → `{ token }`
- `POST /api/vault` — `{ label, ciphertext, drandRound, unlockAt }` (or legacy `{ ciphertext, iv, unlockAt }`)
- `GET /api/vault` — list (metadata only)
- `GET /api/vault/:id` — returns ciphertext if unlocked, 403 if not
- `PATCH /api/vault/:id/extend` — `{ unlockAt }` (must be later)
- `DELETE /api/vault/:id` — only if unlocked

## What this gives you and what it doesn't

It gives you:
- Server can't read your passwords (zero-knowledge: the AES key never leaves your browser).
- Time lock is now cryptographic, not just a server check. Even with full database access and your master password, the outer ciphertext cannot be opened until the drand network publishes the signature for the unlock round. This protects against the developer/operator editing the DB to bypass the lock.

It doesn't give you:
- Protection against a malicious server pushing modified client JS that exfiltrates your master password the next time you log in. Removing this requires distributing the client as a signed/reproducible artifact (browser extension or native app) instead of HTML served by this server.
- Protection against drand being permanently down (locked items would never unlock). drand mainnet has run continuously since 2020 with multiple independent operators, but it is an external dependency.


