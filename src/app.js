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
  const btn = e.target.querySelector('button[type="submit"]');
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
      const lockAtDate = new Date(e.target.lockAt.value);
      if (Number.isNaN(lockAtDate.getTime())) throw new Error('Choose a valid lock date and time');
      if (lockAtDate.getTime() <= Date.now()) throw new Error('Lock time must be in the future');
      if (scheduleAtDate.getTime() <= lockAtDate.getTime()) {
        throw new Error('Schedule unlock time must be later than lock time');
      }
      const { ciphertext, iv } = await aesEncrypt(session.encKey, payload);
      body = {
        label,
        ciphertext,
        iv,
        lockAt: lockAtDate.toISOString(),
        unlockAt: scheduleAt,
      };
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
    setMsg('add', 'Locked.', 'ok');
    refreshSecrets();
    setTimeout(() => {
      const createDialog = document.getElementById('create-dialog');
      if (createDialog && createDialog.open) {
        createDialog.close();
      }
    }, 800);
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

function showConfirmDialog(title, message, isDanger = false) {
  return new Promise((resolve) => {
    const dialog = document.getElementById('confirm-dialog');
    document.getElementById('confirm-dialog-title').textContent = title;
    document.getElementById('confirm-dialog-message').textContent = message;
    const okBtn = dialog.querySelector('button[value="ok"]');
    if (isDanger) {
      okBtn.classList.add('danger');
    } else {
      okBtn.classList.remove('danger');
    }
    
    const handleClose = () => {
      dialog.removeEventListener('close', handleClose);
      resolve(dialog.returnValue === 'ok');
    };
    dialog.addEventListener('close', handleClose);
    dialog.returnValue = '';
    dialog.showModal();
  });
}

function showDateTimeDialog(title, defaultIso) {
  return new Promise((resolve) => {
    const dialog = document.getElementById('datetime-dialog');
    document.getElementById('datetime-dialog-title').textContent = title;
    const input = dialog.querySelector('input[name="datetime"]');
    
    // Convert to local time format for datetime-local input
    const tzOffsetMs = new Date().getTimezoneOffset() * 60000;
    const localDate = new Date(new Date(defaultIso).getTime() - tzOffsetMs);
    input.value = localDate.toISOString().slice(0, 16);

    const handleClose = () => {
      dialog.removeEventListener('close', handleClose);
      if (dialog.returnValue === 'ok') {
        const selectedLocal = new Date(input.value);
        resolve(selectedLocal.toISOString());
      } else {
        resolve(null);
      }
    };
    dialog.addEventListener('close', handleClose);
    dialog.returnValue = '';
    dialog.showModal();
  });
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
    if (item.accessMode === 'lock' && item.lockAt && item.unlockAt) {
      const now = Date.now();
      const lockAtMs = new Date(item.lockAt).getTime();
      const unlockAtMs = new Date(item.unlockAt).getTime();
      if (now < lockAtMs) {
        meta.textContent = `Locks in ${fmtRemaining(lockAtMs - now)} (${new Date(item.lockAt).toLocaleString()})`;
      } else if (now < unlockAtMs) {
        meta.textContent = `Unlocks in ${fmtRemaining(unlockAtMs - now)} (${new Date(item.unlockAt).toLocaleString()})`;
      } else {
        meta.textContent = `Unlocked since ${new Date(item.unlockAt).toLocaleString()}`;
      }
      return;
    }
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
      openRelockDialog(item);
      return;
    }

    if (!item.canRescheduleLater) return;
    const input = await showDateTimeDialog(`New ${item.accessMode} time`, oneDayLaterIso(item.scheduleAt));
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
    const confirmed = await showConfirmDialog('Confirm Delete', `Delete "${item.label}"? This cannot be undone.`, true);
    if (!confirmed) return;
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

let relockTarget = null;

function syncRelockScheduleMode() {
  const form = document.getElementById('relock-form');
  const mode = form.scheduleMode.value;
  const lockAtRow = document.getElementById('relock-lock-at-row');
  const lockAtInput = form.querySelector('input[name="lockAt"]');
  const isLockMode = mode === 'lock';
  if (lockAtRow && lockAtInput) {
    lockAtRow.hidden = !isLockMode;
    lockAtInput.required = isLockMode;
    if (!isLockMode) lockAtInput.value = '';
  }
  document.getElementById('relock-schedule-help').textContent = mode === 'lock'
    ? 'This secret stays revealable until the lock time, then is hidden until the unlock time.'
    : 'This secret is sealed immediately and can only be revealed after the scheduled unlock time.';
}

function syncScheduleMode(form = document.getElementById('add-form')) {
  const mode = form.scheduleMode.value;
  const lockAtRow = document.getElementById('lock-at-row');
  const lockAtInput = form.querySelector('input[name="lockAt"]');
  const isLockMode = mode === 'lock';
  if (lockAtRow && lockAtInput) {
    lockAtRow.hidden = !isLockMode;
    lockAtInput.required = isLockMode;
    if (!isLockMode) lockAtInput.value = '';
  }
  document.getElementById('schedule-at-label').textContent = 'Unlock at';
  document.getElementById('schedule-help').textContent = mode === 'lock'
    ? 'This secret stays revealable until the lock time, then is hidden until the unlock time.'
    : 'This secret is sealed immediately and can only be revealed after the scheduled unlock time.';
}

function setupPasswordToggles() {
  document.querySelectorAll('input[type="password"]').forEach((input) => {
    if (input.dataset.hasToggle === 'true') return;
    input.dataset.hasToggle = 'true';
    const wrapper = document.createElement('span');
    wrapper.className = 'password-field';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.append(input);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'password-toggle';
    btn.textContent = '👁';
    btn.setAttribute('aria-label', 'Show password');
    btn.addEventListener('click', () => {
      const showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      btn.classList.toggle('active', !showing);
      btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
    });
    wrapper.append(btn);
  });
}

document.querySelectorAll('#add-form input[name="scheduleMode"]').forEach(el => {
  el.addEventListener('change', () => syncScheduleMode());
});

document.querySelectorAll('#relock-form input[name="scheduleMode"]').forEach(el => {
  el.addEventListener('change', () => syncRelockScheduleMode());
});

function openCreateDialog() {
  const dialog = document.getElementById('create-dialog');
  const form = document.getElementById('add-form');
  form.reset();
  syncScheduleMode(form);
  setMsg('add', '');
  const min = new Date(Date.now() + 60_000);
  const minLocal = new Date(min.getTime() - min.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  const dt = form.querySelector('input[name="scheduleAt"]');
  const lockDt = form.querySelector('input[name="lockAt"]');
  if (dt) dt.min = minLocal;
  if (lockDt) lockDt.min = minLocal;
  dialog.showModal();
}

document.getElementById('new-secret-btn').addEventListener('click', openCreateDialog);

document.getElementById('close-create-dialog').addEventListener('click', () => {
  document.getElementById('create-dialog').close();
});

document.getElementById('cancel-create').addEventListener('click', () => {
  document.getElementById('create-dialog').close();
});

document.getElementById('create-dialog').addEventListener('close', () => {
  const form = document.getElementById('add-form');
  form.reset();
  syncScheduleMode(form);
  setMsg('add', '');
});

function openRelockDialog(item) {
  relockTarget = item;
  const dialog = document.getElementById('relock-dialog');
  const form = document.getElementById('relock-form');
  form.reset();
  syncRelockScheduleMode();
  setMsg('relock', '');
  document.getElementById('relock-dialog-title').textContent = `Re-lock "${item.label}"`;
  const min = new Date(Date.now() + 60_000);
  const minLocal = new Date(min.getTime() - min.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  const dt = form.querySelector('input[name="scheduleAt"]');
  const lockDt = form.querySelector('input[name="lockAt"]');
  if (dt) dt.min = minLocal;
  if (lockDt) lockDt.min = minLocal;
  dialog.showModal();
}

document.getElementById('relock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!relockTarget) return;
  const item = relockTarget;
  const btn = e.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  setMsg('relock', 'Decrypting…');
  try {
    const scheduleMode = e.target.scheduleMode.value;
    const scheduleAtDate = new Date(e.target.scheduleAt.value);
    if (Number.isNaN(scheduleAtDate.getTime())) throw new Error('Choose a valid date and time');
    if (scheduleAtDate.getTime() <= Date.now()) throw new Error('Unlock time must be in the future');

    const full = await api(`/vault/${item.id}`);
    const plaintext = await decryptSecret(full);

    let body;
    if (scheduleMode === 'lock') {
      const lockAtDate = new Date(e.target.lockAt.value);
      if (Number.isNaN(lockAtDate.getTime())) throw new Error('Choose a valid lock date and time');
      if (lockAtDate.getTime() <= Date.now()) throw new Error('Lock time must be in the future');
      if (scheduleAtDate.getTime() <= lockAtDate.getTime()) {
        throw new Error('Unlock time must be later than lock time');
      }
      setMsg('relock', 'Encrypting…');
      const { ciphertext, iv } = await aesEncrypt(session.encKey, plaintext);
      body = {
        label: item.label,
        ciphertext,
        iv,
        lockAt: lockAtDate.toISOString(),
        unlockAt: scheduleAtDate.toISOString(),
      };
    } else {
      setMsg('relock', 'Sealing with drand timelock…');
      const { ciphertext, drandRound } = await tlockWrap(session.encKey, plaintext, scheduleAtDate.getTime());
      body = {
        label: item.label,
        ciphertext,
        drandRound,
        unlockAt: scheduleAtDate.toISOString(),
      };
    }

    await api(`/vault/${item.id}/relock`, { method: 'POST', body: JSON.stringify(body) });
    setMsg('relock', 'Re-locked.', 'ok');
    refreshSecrets();
    setTimeout(() => {
      const relockDialog = document.getElementById('relock-dialog');
      if (relockDialog && relockDialog.open) {
        relockDialog.close();
      }
    }, 800);
  } catch (err) {
    setMsg('relock', err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('close-relock-dialog').addEventListener('click', () => {
  document.getElementById('relock-dialog').close();
});

document.getElementById('cancel-relock').addEventListener('click', () => {
  document.getElementById('relock-dialog').close();
});

document.getElementById('relock-dialog').addEventListener('close', () => {
  relockTarget = null;
  const form = document.getElementById('relock-form');
  form.reset();
  syncRelockScheduleMode();
  setMsg('relock', '');
});

(function init() {
  session.load();
  if (session.token && session.encKey) {
    show('vault');
  } else {
    if (session.token) session.clear();
    show('auth');
  }

  setupPasswordToggles();
  syncScheduleMode();
  syncRelockScheduleMode();
})();
