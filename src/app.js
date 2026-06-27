import {
  timelockEncrypt, timelockDecrypt, mainnetClient, roundAt, defaultChainInfo, Buffer,
} from 'tlock-js';

const PBKDF2_ITERS = 250_000;
const DRAND_PERIOD_MS = defaultChainInfo.period * 1000;
const enc = new TextEncoder();
const dec = new TextDecoder();
const drand = mainnetClient();

const b64 = {
  encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  },
  decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

async function deriveKeys(password, saltB64) {
  const salt = b64.decode(saltB64);
  const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    pwKey,
    512
  );
  const encKeyRaw = bits.slice(0, 32);
  const authHashRaw = bits.slice(32, 64);
  const encKey = await crypto.subtle.importKey('raw', encKeyRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { encKey, authHash: b64.encode(authHashRaw) };
}

async function aesEncrypt(encKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, enc.encode(plaintext));
  return { ciphertext: b64.encode(ct), iv: b64.encode(iv) };
}

async function aesDecrypt(encKey, ciphertextB64, ivB64) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64.decode(ivB64) },
    encKey,
    b64.decode(ciphertextB64)
  );
  return dec.decode(pt);
}

// Wrap: AES-GCM with master key, then tlock-encrypt the inner blob to the drand round at unlockAt.
// Even with the master password and full DB access, the outer layer cannot be opened until
// the drand network publishes the round signature.
async function tlockWrap(encKey, plaintext, unlockAtMs) {
  const inner = await aesEncrypt(encKey, plaintext);
  const innerBundle = JSON.stringify(inner);
  const round = roundAt(unlockAtMs, defaultChainInfo);
  const outer = await timelockEncrypt(round, Buffer.from(innerBundle, 'utf8'), drand);
  return { ciphertext: outer, drandRound: round };
}

async function tlockUnwrap(encKey, outerCiphertext) {
  const innerBuf = await timelockDecrypt(outerCiphertext, drand);
  const inner = JSON.parse(innerBuf.toString('utf8'));
  return aesDecrypt(encKey, inner.ciphertext, inner.iv);
}

const session = {
  token: null,
  email: null,
  encKey: null,
  load() {
    this.token = sessionStorage.getItem('token');
    this.email = sessionStorage.getItem('email');
  },
  save(token, email) {
    this.token = token;
    this.email = email;
    sessionStorage.setItem('token', token);
    sessionStorage.setItem('email', email);
  },
  clear() {
    this.token = this.email = this.encKey = null;
    sessionStorage.clear();
  },
};

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (session.token) headers.Authorization = `Bearer ${session.token}`;
  const res = await fetch(`/api${path}`, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { status: res.status, data });
  return data;
}

function setMsg(form, text, kind = '') {
  const el = document.querySelector(`.msg[data-for="${form}"]`);
  if (!el) return;
  el.textContent = text;
  el.className = `msg ${kind}`;
}

function show(view) {
  const loggedIn = view === 'vault';
  document.getElementById('auth-view').hidden = loggedIn;
  document.getElementById('vault-view').hidden = !loggedIn;
  document.getElementById('user-bar').hidden = false;
  document.getElementById('user-email').textContent = loggedIn ? session.email : '';
  document.getElementById('logout').textContent = loggedIn ? 'Log out' : 'Log in';
  if (loggedIn) refreshSecrets();
}

document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
    document.getElementById('login-form').hidden = t.dataset.tab !== 'login';
    document.getElementById('signup-form').hidden = t.dataset.tab !== 'signup';
  });
});

document.getElementById('signup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('signup', 'Deriving key…');
  try {
    const email = e.target.email.value.trim().toLowerCase();
    const password = e.target.password.value;
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const salt = b64.encode(saltBytes);
    const { encKey, authHash } = await deriveKeys(password, salt);
    await api('/auth/signup', { method: 'POST', body: JSON.stringify({ email, salt, authHash }) });
    const { token } = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email, authHash }) });
    session.save(token, email);
    session.encKey = encKey;
    show('vault');
  } catch (err) {
    setMsg('signup', err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('login', 'Deriving key…');
  try {
    const email = e.target.email.value.trim().toLowerCase();
    const password = e.target.password.value;
    const { salt } = await api('/auth/salt', { method: 'POST', body: JSON.stringify({ email }) });
    const { encKey, authHash } = await deriveKeys(password, salt);
    const { token } = await api('/auth/login', { method: 'POST', body: JSON.stringify({ email, authHash }) });
    session.save(token, email);
    session.encKey = encKey;
    show('vault');
  } catch (err) {
    setMsg('login', err.status === 401 ? 'Invalid credentials' : err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('logout').addEventListener('click', () => {
  if (session.token) {
    session.clear();
    location.reload();
  } else {
    document.querySelector('#login-form input[name="email"]')?.focus();
  }
});

document.getElementById('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  setMsg('add', 'Encrypting…');
  try {
    const scheduleMode = e.target.scheduleMode.value;
    const label = e.target.label.value.trim();
    const payload = JSON.stringify({
      value: e.target.value.value,
      recoveryEmail: e.target.recoveryEmail.value || null,
      recoveryEmailPassword: e.target.recoveryEmailPassword.value || null,
    });
    const scheduleAtDate = new Date(e.target.scheduleAt.value);
    if (Number.isNaN(scheduleAtDate.getTime())) throw new Error('Choose a valid date and time');
    const scheduleAt = scheduleAtDate.toISOString();
    let body;
    if (scheduleMode === 'lock') {
      const { ciphertext, iv } = await aesEncrypt(session.encKey, payload);
      body = { label, ciphertext, iv, lockAt: scheduleAt };
    } else {
      setMsg('add', 'Sealing with drand timelock…');
      const { ciphertext, drandRound } = await tlockWrap(session.encKey, payload, scheduleAtDate.getTime());
      body = {
        label,
        ciphertext,
        drandRound,
        unlockAt: scheduleAt,
      };
    }
    await api('/vault', { method: 'POST', body: JSON.stringify(body) });
    e.target.reset();
    syncScheduleMode(e.target);
    setMsg('add', 'Locked.', 'ok');
    refreshSecrets();
  } catch (err) {
    setMsg('add', err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

function fmtRemaining(ms) {
  if (ms <= 0) return 'unlocked';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}

async function refreshSecrets() {
  const list = document.getElementById('secrets-list');
  try {
    const items = await api('/vault');
    list.innerHTML = '';
    list.classList.toggle('empty', items.length === 0);
    for (const item of items) renderSecret(list, item);
  } catch (err) {
    if (err.status === 401) {
      session.clear();
      show('auth');
    }
  }
}

async function decryptSecret(full) {
  if (full.lockAt) {
    return aesDecrypt(session.encKey, full.ciphertext, full.iv);
  }
  if (full.drandRound) {
    return tlockUnwrap(session.encKey, full.ciphertext);
  }
  return aesDecrypt(session.encKey, full.ciphertext, full.iv);
}

function oneDayLaterIso(dateString) {
  const parsed = dateString ? new Date(dateString).getTime() : Date.now();
  const start = Number.isNaN(parsed) ? Date.now() : Math.max(parsed, Date.now());
  return new Date(start + 24 * 3600 * 1000).toISOString();
}

function renderSecret(list, item) {
  const li = document.createElement('li');
  li.className = `secret ${item.accessible ? 'accessible' : 'locked'}`;
  li.dataset.id = item.id;

  const head = document.createElement('div');
  head.className = 'secret-head';

  const labelWrap = document.createElement('div');
  const labelEl = document.createElement('div');
  labelEl.className = 'secret-label';
  labelEl.textContent = item.label;
  const meta = document.createElement('div');
  meta.className = 'secret-meta';
  const updateMeta = () => {
    const scheduleAt = new Date(item.scheduleAt).getTime();
    const remaining = scheduleAt - Date.now();
    meta.textContent = item.accessMode === 'lock'
      ? (remaining <= 0
        ? `Locked since ${new Date(item.scheduleAt).toLocaleString()}`
        : `Locks in ${fmtRemaining(remaining)} (${new Date(item.scheduleAt).toLocaleString()})`)
      : (remaining <= 0
        ? `Unlocked since ${new Date(item.scheduleAt).toLocaleString()}`
        : `Unlocks in ${fmtRemaining(remaining)} (${new Date(item.scheduleAt).toLocaleString()})`);
  };
  updateMeta();
  labelWrap.append(labelEl, meta);

  const actions = document.createElement('div');
  actions.className = 'secret-actions';

  const revealBtn = document.createElement('button');
  revealBtn.textContent = item.accessible ? 'Reveal' : 'Locked';
  revealBtn.disabled = !item.accessible;

  const extendBtn = document.createElement('button');
  extendBtn.textContent = item.accessMode === 'lock' ? 'Postpone' : 'Re-create';
  extendBtn.disabled = item.accessMode === 'lock' ? !item.canRescheduleLater : !item.accessible;

  const delBtn = document.createElement('button');
  delBtn.textContent = 'Delete';
  delBtn.className = 'danger';
  delBtn.disabled = item.accessMode === 'unlock' && !item.accessible;

  actions.append(revealBtn, extendBtn, delBtn);
  head.append(labelWrap, actions);
  li.append(head);

  revealBtn.addEventListener('click', async () => {
    revealBtn.disabled = true;
    try {
      const full = await api(`/vault/${item.id}`);
      const plaintext = await decryptSecret(full);
      let body = li.querySelector('.secret-body');
      if (!body) {
        body = document.createElement('div');
        body.className = 'secret-body';
        li.append(body);
      }
      let parsed;
      try { parsed = JSON.parse(plaintext); } catch { parsed = null; }
      if (parsed && typeof parsed === 'object' && 'value' in parsed) {
        const lines = [`Secret: ${parsed.value}`];
        if (parsed.recoveryEmail) lines.push(`Recovery email: ${parsed.recoveryEmail}`);
        if (parsed.recoveryEmailPassword) lines.push(`Recovery email password: ${parsed.recoveryEmailPassword}`);
        body.textContent = lines.join('\n');
      } else {
        body.textContent = plaintext;
      }
    } catch (err) {
      alert(`Could not decrypt: ${err.message}`);
    } finally {
      revealBtn.disabled = false;
    }
  });

  extendBtn.addEventListener('click', async () => {
    if (item.accessMode === 'unlock') {
      if (!item.accessible) return;
      if (!confirm(`Re-lock "${item.label}"? You will choose a new unlock time and the current unlocked copy will be replaced.`)) return;
      const input = prompt('New unlock date/time (ISO 8601, e.g. YYYY-MM-DDTHH:mm:ss.SSSZ; must be in the future):', oneDayLaterIso(item.scheduleAt));
      if (!input) return;
      extendBtn.disabled = true;
      try {
        const unlockAtDate = new Date(input);
        if (Number.isNaN(unlockAtDate.getTime())) throw new Error('Choose a valid date and time');
        if (unlockAtDate.getTime() <= Date.now()) throw new Error('New unlock time must be in the future');
        const full = await api(`/vault/${item.id}`);
        const plaintext = await decryptSecret(full);
        const { ciphertext, drandRound } = await tlockWrap(session.encKey, plaintext, unlockAtDate.getTime());
        await api(`/vault/${item.id}/relock`, {
          method: 'POST',
          body: JSON.stringify({
            label: item.label,
            ciphertext,
            drandRound,
            unlockAt: unlockAtDate.toISOString(),
          }),
        });
        refreshSecrets();
      } catch (err) {
        alert(err.message);
        extendBtn.disabled = false;
      }
      return;
    }

    if (!item.canRescheduleLater) return;
    const input = prompt(`New ${item.accessMode} date/time (ISO, must be later than the current scheduled time):`,
      oneDayLaterIso(item.scheduleAt));
    if (!input) return;
    try {
      const newDate = new Date(input).toISOString();
      await api(`/vault/${item.id}/extend`, { method: 'PATCH', body: JSON.stringify({ scheduleAt: newDate }) });
      refreshSecrets();
    } catch (err) {
      alert(err.message);
    }
  });

  delBtn.addEventListener('click', async () => {
    if (!confirm(`Delete "${item.label}"? This cannot be undone.`)) return;
    try {
      await api(`/vault/${item.id}`, { method: 'DELETE' });
      refreshSecrets();
    } catch (err) {
      alert(err.message);
    }
  });

  const scheduleAtMs = new Date(item.scheduleAt).getTime();
  const msUntilStateChange = scheduleAtMs - Date.now();
  if (msUntilStateChange > 0) {
    const tick = setInterval(() => {
      const remaining = scheduleAtMs - Date.now();
      if (remaining <= 0) {
        clearInterval(tick);
        refreshSecrets();
      } else {
        updateMeta();
      }
    }, 1000);
  }

  list.append(li);
}

function syncScheduleMode(form = document.getElementById('add-form')) {
  const mode = form.scheduleMode.value;
  document.getElementById('schedule-at-label').textContent = mode === 'lock' ? 'Lock at' : 'Unlock at';
  document.getElementById('schedule-help').textContent = mode === 'lock'
    ? 'This secret stays revealable until the scheduled lock time, then the server will stop returning it.'
    : 'This secret is sealed immediately and can only be revealed after the scheduled unlock time.';
}

document.querySelectorAll('#add-form input[name="scheduleMode"]').forEach(el => {
  el.addEventListener('change', () => syncScheduleMode());
});

(function init() {
  session.load();
  if (session.token && session.encKey) {
    show('vault');
  } else {
    if (session.token) session.clear();
    show('auth');
  }

  const dt = document.querySelector('#add-form input[name="scheduleAt"]');
  const min = new Date(Date.now() + 60_000);
  dt.min = new Date(min.getTime() - min.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  syncScheduleMode();
})();
