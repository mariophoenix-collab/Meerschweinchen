'use strict';
/* =====================================================================
   Meine Meerschweinchen – OneDrive-Anbindung
   ---------------------------------------------------------------------
   Anmeldung:  OAuth 2.0 Autorisierungscode-Flow mit PKCE (Microsoft
               Identity Platform, «Single-page application»). Kein
               Client-Geheimnis, kein Passwort wird gespeichert.
   Token:      Zugriffstoken nur im Arbeitsspeicher. Das Aktualisierungs-
               token liegt verschlüsselt (AES-256-GCM) in IndexedDB; der
               Schlüssel ist «nicht exportierbar» und verlässt das Gerät nie.
   Berechtigung: nur Files.ReadWrite.AppFolder → die App sieht in OneDrive
               ausschliesslich ihren eigenen Ordner «Apps/Meine Meerschweinchen».
   Abgleich:   Jedes Gerät schreibt nur in seinen eigenen Ordner unter
               «Synchronisierung/<Geräte-ID>/». Dadurch überschreiben sich
               Geräte nie gegenseitig. Jeder Datensatz trägt einen
               Versionsvektor; gleichzeitige Änderungen werden erkannt, die
               neuere Version gewinnt, die andere bleibt unter «Konflikte»
               erhalten und lässt sich wiederherstellen.
   ===================================================================== */

const GRAPH = 'https://graph.microsoft.com/v1.0';
const SCOPES = 'openid profile offline_access Files.ReadWrite.AppFolder';
const SYNC_DIR = 'Synchronisierung';
const BACKUP_DIR = 'Datenbank-Backups';
const APPBACKUP_DIR = 'App-Backups';
const ROOT_FOLDERS = ['Datenbank-Backups', 'App-Backups', 'Meerschweinchen', 'Smart-Home-Daten', 'Temperaturverläufe', 'Wetterdaten', 'Kassenzettel', 'PDF-Berichte', 'Synchronisierung'];
const PIG_FOLDERS = ['Gesundheitsdaten', 'Gewicht', 'Fotos', 'Tierarzt', 'Dokumente', 'Kosten'];
const LOCAL_TABLES = new Set(['conflicts']);
const SILENT_TABLES = new Set(['settings', 'completions', 'doses', 'weatherlog']);
const APP_VERSION = '2.0';
const KEEP_AUTO_BACKUPS = 90;

const LS = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const backoff = (n) => Math.min(30000, 800 * 2 ** n) + Math.random() * 400;
const b64u = {
  enc(buf) { const u = new Uint8Array(buf); let s = ''; for (const c of u) s += String.fromCharCode(c); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  rand(n) { return this.enc(crypto.getRandomValues(new Uint8Array(n))); },
};
const B64 = {
  enc(buf) { const u = new Uint8Array(buf); let s = ''; for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); },
  dec(str) { const s = atob(str); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; },
};
function parseJwt(t) { try { const p = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'); return JSON.parse(decodeURIComponent(escape(atob(p + '==='.slice((p.length + 3) % 4))))); } catch { return {}; } }
async function sha256(text) { return B64.enc(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))); }

class CloudError extends Error { constructor(code, msg, status) { super(msg); this.code = code; this.status = status; } }

// ---------------- Gerät ----------------
function guessDeviceName() {
  const ua = navigator.userAgent || '';
  if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/Android/.test(ua)) return /Mobile/.test(ua) ? 'Android-Handy' : 'Android-Tablet';
  if (/Windows/.test(ua)) return 'Windows-PC';
  if (/Macintosh/.test(ua)) return 'Mac';
  return 'Gerät';
}
const Device = {
  _d: null,
  get d() {
    if (!this._d) {
      this._d = LS.get('mm-device', null);
      if (!this._d || !this._d.id) { this._d = { id: 'g-' + b64u.rand(9).replace(/[-_]/g, 'x'), name: guessDeviceName() }; LS.set('mm-device', this._d); }
    }
    return this._d;
  },
  get id() { return this.d.id; },
  get name() { return this.d.name; },
  rename(n) { this._d = { ...this.d, name: String(n || '').trim().slice(0, 40) || guessDeviceName() }; LS.set('mm-device', this._d); },
};

// ---------------- Versionsvektoren ----------------
function vvCompare(a = {}, b = {}) {
  let gt = false, lt = false;
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = a[k] || 0, y = b[k] || 0;
    if (x > y) gt = true; else if (x < y) lt = true;
  }
  return gt && lt ? 'concurrent' : gt ? 'gt' : lt ? 'lt' : 'eq';
}
function vvMax(a = {}, b = {}) { const o = { ...a }; for (const [k, v] of Object.entries(b)) o[k] = Math.max(o[k] || 0, v); return o; }

// ---------------- Token-Tresor ----------------
const TokenVault = {
  mem: null,
  async key() {
    let k = await S.metaGet('tokenKey');
    if (!k) { k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); await S.metaSet('tokenKey', k); }
    return k;
  },
  async save(rt) {
    this.mem = rt;
    if (!S.persistent) return;
    const k = await this.key(), iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(rt));
    await S.metaSet('tokenBlob', { iv, ct });
  },
  async load() {
    if (this.mem) return this.mem;
    const b = await S.metaGet('tokenBlob'); if (!b) return null;
    try { const k = await this.key(); this.mem = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.iv }, k, b.ct)); return this.mem; } catch { return null; }
  },
  async clear() { this.mem = null; await S.metaDel('tokenBlob'); },
};

// ---------------- Anmeldung (OAuth 2.0 + PKCE) ----------------
function friendlyAuthError(code, desc = '') {
  const d = String(desc || '');
  if (/AADSTS50011/.test(d)) return `Die Rücksprung-Adresse stimmt nicht mit der App-Registrierung überein. Tragen Sie in Azure genau diese Adresse als «Single-page application» ein: ${Auth.redirectUri()}`;
  if (/AADSTS700016|AADSTS700038/.test(d) || code === 'unauthorized_client') return 'Die Client-ID ist unbekannt. Bitte die «Anwendungs-ID (Client-ID)» aus der App-Registrierung prüfen.';
  if (/AADSTS9002326|AADSTS9002327/.test(d)) return 'Die Rücksprung-Adresse ist in Azure als «Web» statt als «Single-page application» eingetragen. Bitte unter «Authentifizierung» als SPA hinzufügen.';
  if (/AADSTS50020|AADSTS500200/.test(d)) return 'Dieses Konto wird von der App-Registrierung nicht unterstützt. Prüfen Sie «Unterstützte Kontotypen» bzw. die Einstellung «Kontotyp» in der App.';
  if (code === 'access_denied') return 'Die Anmeldung wurde abgebrochen oder der Zugriff nicht erlaubt.';
  if (code === 'consent_required') return 'Bitte bestätigen Sie bei der Anmeldung den Zugriff auf den App-Ordner.';
  return `Anmeldung bei Microsoft fehlgeschlagen (${code || 'Fehler'}).${d ? ' ' + d.split('\n')[0].slice(0, 180) : ''}`;
}

const Auth = {
  access: null, accessExp: 0, needsLogin: false, _refreshing: null, lastError: '',
  cfg() {
    const o = LS.get('mm-cloud-cfg', {}), a = window.APP_CONFIG || {};
    return { clientId: String(o.clientId || a.clientId || '').trim(), authority: o.authority || a.authority || 'consumers', fromFile: !o.clientId && !!a.clientId };
  },
  setCfg(p) { LS.set('mm-cloud-cfg', { ...LS.get('mm-cloud-cfg', {}), ...p }); },
  configured() { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(this.cfg().clientId); },
  redirectUri() { return location.origin + location.pathname.replace(/index\.html$/, ''); },
  base() { return `https://login.microsoftonline.com/${encodeURIComponent(this.cfg().authority)}/oauth2/v2.0`; },
  account() { return LS.get('mm-account', null); },
  signedIn() { return !!this.account(); },
  async login({ silent = false } = {}) {
    if (!this.configured()) throw new CloudError('config', 'Bitte zuerst die Client-ID eintragen.');
    if (!crypto.subtle) throw new CloudError('config', 'Die Anmeldung braucht eine sichere Verbindung (https).');
    const verifier = b64u.rand(48), state = b64u.rand(16);
    const challenge = b64u.enc(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    LS.set('mm-auth-pending', { state, verifier, at: Date.now(), hash: location.hash, silent });
    const acc = this.account();
    const p = new URLSearchParams({ client_id: this.cfg().clientId, response_type: 'code', redirect_uri: this.redirectUri(), response_mode: 'query', scope: SCOPES, state, code_challenge: challenge, code_challenge_method: 'S256' });
    if (silent) p.set('prompt', 'none');
    else if (!acc) p.set('prompt', 'select_account');
    if (acc?.username) p.set('login_hint', acc.username);
    location.assign(`${this.base()}/authorize?${p}`);
    return new Promise(() => {}); // Seite wird verlassen
  },
  /** Verarbeitet die Rückkehr von Microsoft (…/?code=…&state=…). */
  async handleRedirect() {
    const q = new URLSearchParams(location.search);
    if (!q.has('code') && !q.has('error')) return null;
    const pend = LS.get('mm-auth-pending', null); LS.del('mm-auth-pending');
    history.replaceState(null, '', location.pathname + (pend?.hash || '#cloud'));
    if (!pend || q.get('state') !== pend.state || Date.now() - pend.at > 20 * 60000) return { error: 'Die Anmeldung konnte nicht zugeordnet werden (abgelaufen oder in anderem Fenster gestartet). Bitte erneut anmelden.' };
    if (q.has('error')) {
      const e = q.get('error');
      if (pend.silent && /login_required|interaction_required|consent_required|account_selection_required/.test(e)) { this.needsLogin = true; return { silentFailed: true }; }
      return { error: friendlyAuthError(e, q.get('error_description')) };
    }
    try {
      const tok = await this._tokenRequest({ grant_type: 'authorization_code', code: q.get('code'), redirect_uri: this.redirectUri(), code_verifier: pend.verifier });
      const prevOid = this.account()?.oid;
      await this._store(tok, true);
      return { ok: true, switched: !!prevOid && prevOid !== this.account()?.oid };
    } catch (e) { return { error: e.message }; }
  },
  async _tokenRequest(params) {
    const body = new URLSearchParams({ client_id: this.cfg().clientId, scope: SCOPES, ...params });
    let res;
    try { res = await fetch(`${this.base()}/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }); }
    catch { throw new CloudError(navigator.onLine === false ? 'offline' : 'network', 'Microsoft ist gerade nicht erreichbar.'); }
    const j = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (j.error === 'invalid_grant' || j.error === 'interaction_required' || j.error === 'login_required') throw new CloudError('login', 'Die Anmeldung bei Microsoft ist abgelaufen. Bitte kurz neu anmelden.');
      throw new CloudError('auth', friendlyAuthError(j.error, j.error_description));
    }
    return j;
  },
  async _store(tok, fresh) {
    this.access = tok.access_token; this.accessExp = Date.now() + (+tok.expires_in || 3600) * 1000;
    if (tok.refresh_token) await TokenVault.save(tok.refresh_token);
    const prev = this.account() || {};
    if (tok.id_token) {
      const c = parseJwt(tok.id_token);
      LS.set('mm-account', { name: c.name || '', username: c.preferred_username || c.email || '', oid: c.oid || c.sub || '', since: fresh ? Date.now() : prev.since || Date.now(), loginAt: fresh ? Date.now() : prev.loginAt || Date.now() });
    } else if (!this.account()) LS.set('mm-account', { name: '', username: '', since: Date.now(), loginAt: Date.now() });
    this.needsLogin = false; this.lastError = '';
  },
  async token() {
    if (this.access && Date.now() < this.accessExp - 120000) return this.access;
    if (!this.signedIn()) throw new CloudError('signedout', 'Nicht mit Microsoft verbunden.');
    if (this._refreshing) return this._refreshing;
    this._refreshing = (async () => {
      const rt = await TokenVault.load();
      if (!rt) { this.needsLogin = true; throw new CloudError('login', 'Bitte kurz neu bei Microsoft anmelden.'); }
      try { const tok = await this._tokenRequest({ grant_type: 'refresh_token', refresh_token: rt }); await this._store(tok, false); return this.access; }
      catch (e) { if (e.code === 'login') { this.needsLogin = true; await TokenVault.clear(); } throw e; }
    })().finally(() => { this._refreshing = null; });
    return this._refreshing;
  },
  async logout() { this.access = null; this.accessExp = 0; await TokenVault.clear(); LS.del('mm-account'); this.needsLogin = false; },
};

// ---------------- Microsoft Graph ----------------
function graphError(status, e = {}) {
  const code = e.code || '';
  let msg, c = 'graph';
  if (status === 401) { msg = 'Die Anmeldung bei Microsoft ist abgelaufen.'; c = 'login'; }
  else if (status === 403) msg = 'Microsoft verweigert den Zugriff auf OneDrive. Bitte Verbindung trennen und neu anmelden.';
  else if (status === 404) { msg = 'Datei oder Ordner in OneDrive nicht gefunden.'; c = 'notfound'; }
  else if (status === 409) { msg = 'In OneDrive gibt es bereits eine Datei mit diesem Namen.'; c = 'exists'; }
  else if (status === 507 || code === 'quotaLimitReached' || code === 'insufficientStorage') { msg = 'Ihr OneDrive-Speicher ist voll. Bitte Platz schaffen oder den Speicher erweitern.'; c = 'quota'; }
  else if (status === 413) msg = 'Die Datei ist zu gross für OneDrive.';
  else if (status === 423) msg = 'Die Datei ist in OneDrive gerade gesperrt. Es wird später erneut versucht.';
  else msg = `OneDrive meldet einen Fehler (${status}${code ? ', ' + code : ''}).`;
  return new CloudError(c, msg, status);
}
const encPath = (p) => String(p).split('/').filter(Boolean).map(encodeURIComponent).join('/');
const ap = (p) => (p ? `/me/drive/special/approot:/${encPath(p)}:` : '/me/drive/special/approot');
const kids = (p) => (p ? `${ap(p)}/children` : '/me/drive/special/approot/children');
const dirOf = (p) => String(p).split('/').slice(0, -1).join('/');
const safeName = (s, max = 80) => (String(s || '').replace(/["*:<>?/\\|#%\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().replace(/^[.\s]+|[.\s]+$/g, '').slice(0, max) || 'Ohne Namen');

const G = {
  async req(method, path, { body, type, raw, tries = 4 } = {}) {
    const url = path.startsWith('https://') ? path : GRAPH + path;
    for (let attempt = 0; ; attempt++) {
      const tok = await Auth.token();
      const headers = { Authorization: 'Bearer ' + tok };
      let b = body;
      if (body !== undefined && !(body instanceof Blob) && typeof body !== 'string') { headers['Content-Type'] = 'application/json'; b = JSON.stringify(body); }
      else if (type) headers['Content-Type'] = type;
      let res;
      try { res = await fetch(url, { method, headers, body: b }); }
      catch {
        if (navigator.onLine === false) throw new CloudError('offline', 'Keine Internetverbindung.');
        if (attempt < tries) { await sleep(backoff(attempt)); continue; }
        throw new CloudError('network', 'OneDrive ist gerade nicht erreichbar.');
      }
      if (res.status === 401 && attempt < 1) { Auth.access = null; continue; }
      if ([429, 500, 502, 503, 504].includes(res.status) && attempt < tries) { const ra = +res.headers.get('Retry-After'); await sleep(ra ? Math.min(ra, 60) * 1000 : backoff(attempt)); continue; }
      if (!res.ok) { const j = await res.json().catch(() => ({})); throw graphError(res.status, j.error); }
      if (raw) return res;
      if (res.status === 204) return null;
      return (res.headers.get('Content-Type') || '').includes('json') ? res.json() : res;
    }
  },
  async list(p) {
    const out = []; let url = kids(p) + '?$top=500';
    while (url) { const j = await this.req('GET', url); out.push(...(j.value || [])); url = j['@odata.nextLink'] || null; }
    return out;
  },
  async listOrEmpty(p) { try { return await this.list(p); } catch (e) { if (e.code === 'notfound') return []; throw e; } },
  async mkdir(parent, name) {
    try { await this.req('POST', kids(parent), { body: { name, folder: {}, '@microsoft.graph.conflictBehavior': 'fail' } }); }
    catch (e) { if (e.code !== 'exists') throw e; }
  },
  async put(path, data, { rename = false, type } = {}) {
    const blob = data instanceof Blob ? data : new Blob([data], { type: type || 'application/json' });
    const cb = rename ? 'rename' : 'replace';
    if (blob.size <= 4 * 1024 * 1024) return this.req('PUT', `${ap(path)}/content?@microsoft.graph.conflictBehavior=${cb}`, { body: blob, type: blob.type || 'application/octet-stream' });
    const s = await this.req('POST', `${ap(path)}/createUploadSession`, { body: { item: { '@microsoft.graph.conflictBehavior': cb } } });
    const CH = 320 * 1024 * 10; let res = null;
    for (let start = 0; start < blob.size; start += CH) {
      const end = Math.min(start + CH, blob.size);
      for (let a = 0; ; a++) {
        try {
          res = await fetch(s.uploadUrl, { method: 'PUT', headers: { 'Content-Range': `bytes ${start}-${end - 1}/${blob.size}` }, body: blob.slice(start, end) });
          if (res.ok || res.status === 202) break;
          if (a < 3 && res.status >= 500) { await sleep(backoff(a)); continue; }
          const j = await res.json().catch(() => ({})); throw graphError(res.status, j.error);
        } catch (e) { if (e instanceof CloudError) throw e; if (a < 3) { await sleep(backoff(a)); continue; } throw new CloudError('network', 'Hochladen unterbrochen. Es wird später erneut versucht.'); }
      }
    }
    return res.json();
  },
  async download(item) {
    let url = item['@microsoft.graph.downloadUrl'];
    if (!url) { const it = await this.req('GET', `/me/drive/items/${encodeURIComponent(item.id)}`); url = it['@microsoft.graph.downloadUrl']; }
    if (!url) throw new CloudError('graph', 'OneDrive liefert keinen Download-Link.');
    let res; try { res = await fetch(url); } catch { throw new CloudError('network', 'Download aus OneDrive fehlgeschlagen.'); }
    if (!res.ok) throw graphError(res.status, {});
    return res;
  },
  async item(path) { return this.req('GET', ap(path)); },
  async remove(id) { try { await this.req('DELETE', `/me/drive/items/${encodeURIComponent(id)}`); } catch (e) { if (e.code !== 'notfound') throw e; } },
  async rename(path, name) {
    try { await this.req('PATCH', ap(path), { body: { name } }); return true; }
    catch (e) {
      if (e.code === 'notfound') return false;
      if (e.code !== 'exists') throw e;
      await this.mergeInto(path, (dirOf(path) ? dirOf(path) + '/' : '') + name); return true; // Ziel gibt es schon: Inhalte zusammenführen
    }
  },
  /** Verschiebt alle Inhalte von src nach dst (beides Ordner) und legt src danach in den OneDrive-Papierkorb. */
  async mergeInto(src, dst) {
    const target = await this.item(dst), have = new Map((await this.list(dst)).map((x) => [x.name.toLowerCase(), x]));
    for (const c of await this.list(src)) {
      const ex = have.get(c.name.toLowerCase());
      if (c.folder && ex?.folder) { await this.mergeInto(`${src}/${c.name}`, `${dst}/${c.name}`); continue; }
      let name = c.name;
      if (ex) { const dot = c.name.lastIndexOf('.'), stem = dot > 0 ? c.name.slice(0, dot) : c.name, ext = dot > 0 ? c.name.slice(dot) : ''; let n = 2; while (have.has(`${stem} (${n})${ext}`.toLowerCase())) n++; name = `${stem} (${n})${ext}`; }
      await this.req('PATCH', `/me/drive/items/${encodeURIComponent(c.id)}`, { body: { name, parentReference: { id: target.id } } });
      have.set(name.toLowerCase(), c);
    }
    const left = await this.listOrEmpty(src);
    if (!left.length) { try { await this.remove((await this.item(src)).id); } catch {} }
  },
};

// ---------------- Pfade in OneDrive ----------------
function animalFolder(a) {
  if (!a) return 'Meerschweinchen/Alle Tiere';
  const name = safeName(a.name, 60);
  const twins = S.list('animals').filter((x) => x.id !== a.id && safeName(x.name, 60).toLowerCase() === name.toLowerCase());
  return `Meerschweinchen/${twins.length ? `${name} ${a.id.slice(0, 4)}` : name}`;
}
const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/heic': 'heic', 'image/gif': 'gif', 'image/webp': 'webp', 'video/mp4': 'mp4', 'video/quicktime': 'mov', 'application/pdf': 'pdf' };
function mediaPath(m) {
  const a = m.animalId ? (S.get('animals', m.animalId) || S.recs.get('animals:' + m.animalId)?.data) : null;
  const base = animalFolder(a);
  const visual = /^(image|video)\//.test(m.mime || '');
  const dir = m.entity === 'expense' ? 'Kassenzettel'
    : m.entity === 'report' ? `PDF-Berichte/${a ? safeName(a.name, 60) : 'Allgemein'}`
    : m.entity === 'journal' ? `${base}/Gesundheitsdaten`
    : m.entity === 'visit' ? `${base}/Tierarzt`
    : `${base}/${visual ? 'Fotos' : 'Dokumente'}`;
  const ext = (m.name && /\.([a-z0-9]{2,5})$/i.exec(m.name)?.[1]) || EXT[m.mime] || 'bin';
  const label = m.caption || (m.name ? m.name.replace(/\.[^.]+$/, '') : visual ? 'Foto' : 'Dokument');
  const prefix = m.entity === 'report' ? '' : String(m.takenAt || '').slice(0, 10) + ' ';
  return `${dir}/${safeName(prefix + label, 90)}.${ext.toLowerCase()}`;
}

// ---------------- Verschlüsselte Backups ----------------
const ITER2 = 310000;
async function deriveKey(pw, salt, iter = ITER2) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pw).normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function gz(bytes, dir) {
  const S2 = dir === 'c' ? window.CompressionStream : window.DecompressionStream;
  const s = new Blob([bytes]).stream().pipeThrough(new S2('gzip'));
  return new Uint8Array(await new Response(s).arrayBuffer());
}
const Backup = {
  KEYFILE: `${BACKUP_DIR}/schluessel.json`,
  async localKey() { return S.metaGet('backupKey'); },
  async status() {
    const k = await this.localKey();
    if (k) return 'ready';
    try { await G.item(this.KEYFILE); return 'needs-password'; } catch (e) { if (e.code === 'notfound') return 'none'; throw e; }
  },
  /** Backup-Passwort festlegen (erstes Gerät) oder bestätigen (weitere Geräte). */
  async setup(pw) {
    if (String(pw).length < 8) throw new CloudError('input', 'Das Passwort braucht mindestens 8 Zeichen.');
    let remote = null;
    try { remote = await (await G.download(await G.item(this.KEYFILE))).json(); } catch (e) { if (e.code !== 'notfound') throw e; }
    if (remote) {
      const salt = B64.dec(remote.salt), key = await deriveKey(pw, salt, remote.iter);
      try { await crypto.subtle.decrypt({ name: 'AES-GCM', iv: B64.dec(remote.check.iv) }, key, B64.dec(remote.check.data)); }
      catch { throw new CloudError('input', 'Das Passwort passt nicht zum Backup-Passwort, das auf Ihrem anderen Gerät festgelegt wurde.'); }
      await S.metaSet('backupKey', { key, salt: remote.salt, iter: remote.iter });
      return 'verified';
    }
    const salt = crypto.getRandomValues(new Uint8Array(16)), key = await deriveKey(pw, salt), iv = crypto.getRandomValues(new Uint8Array(12));
    const check = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode('meine-meerschweinchen'));
    await G.put(this.KEYFILE, JSON.stringify({ format: 'mm-key', v: 1, kdf: 'PBKDF2-SHA256', iter: ITER2, salt: B64.enc(salt), check: { iv: B64.enc(iv), data: B64.enc(check) }, createdAt: new Date().toISOString(), hinweis: 'Enthält kein Passwort, nur Prüfdaten. Bitte nicht löschen.' }, null, 1));
    await S.metaSet('backupKey', { key, salt: B64.enc(salt), iter: ITER2 });
    return 'created';
  },
  async forget() { await S.metaDel('backupKey'); },
  async encrypt(payloadObj, k) {
    let bytes = new TextEncoder().encode(JSON.stringify(payloadObj)), packed = false;
    if (window.CompressionStream) { try { bytes = await gz(bytes, 'c'); packed = true; } catch {} }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k.key, bytes);
    return { iv: B64.enc(iv), data: B64.enc(ct), gz: packed };
  },
  async create(reason = 'automatisch', dir = BACKUP_DIR) {
    const k = await this.localKey();
    if (!k) throw new CloudError('nokey', 'Für verschlüsselte Backups bitte zuerst ein Backup-Passwort festlegen.');
    const records = [...S.recs.values()].filter((r) => !LOCAL_TABLES.has(r.tbl));
    const now = new Date();
    const enc = await this.encrypt({ format: 'mm-data', v: 2, createdAt: now.toISOString(), reason, device: Device.name, records }, k);
    const p2 = (n) => String(n).padStart(2, '0');
    const stamp = `${now.getFullYear()}-${p2(now.getMonth() + 1)}-${p2(now.getDate())} ${p2(now.getHours())}-${p2(now.getMinutes())}`;
    const file = { format: 'mm-backup', v: 2, app: 'Meine Meerschweinchen', cipher: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iter: k.iter, salt: k.salt, createdAt: now.toISOString(), reason, device: Device.name, count: records.filter((r) => !r.deleted).length, ...enc };
    const item = await G.put(`${dir}/Backup ${stamp} (${safeName(reason, 40)}).json`, JSON.stringify(file), { rename: true });
    if (dir === BACKUP_DIR) { Cloud.st.lastBackupAt = Date.now(); Cloud.st.lastBackupName = item?.name || ''; this.prune().catch(() => {}); }
    else { Cloud.st.lastSafetyAt = Date.now(); }
    Cloud.saveState();
    return item;
  },
  async list() {
    const out = [];
    for (const dir of [BACKUP_DIR, APPBACKUP_DIR]) for (const f of await G.listOrEmpty(dir)) if (f.file && /^Backup .*\.json$/.test(f.name)) out.push({ ...f, dir });
    return out.sort((a, b) => String(b.createdDateTime || b.name).localeCompare(String(a.createdDateTime || a.name)));
  },
  async prune() {
    const auto = (await G.listOrEmpty(BACKUP_DIR)).filter((f) => f.file && /^Backup .*\.json$/.test(f.name)).sort((a, b) => String(b.createdDateTime).localeCompare(String(a.createdDateTime)));
    for (const f of auto.slice(KEEP_AUTO_BACKUPS)) await G.remove(f.id); // landet im OneDrive-Papierkorb
  },
  /** Lädt und entschlüsselt ein Backup. Ohne Passwort wird der gespeicherte Schlüssel verwendet. */
  async read(item, pw) {
    const f = await (await G.download(item)).json().catch(() => { throw new CloudError('input', 'Die Datei ist kein lesbares Backup.'); });
    return this.decryptFile(f, pw);
  },
  async decryptFile(f, pw) {
    if (f.format !== 'mm-backup') throw new CloudError('input', 'Die Datei ist kein Backup von «Meine Meerschweinchen».');
    let key = null; const k = await this.localKey();
    if (pw) key = await deriveKey(pw, B64.dec(f.salt), f.iter);
    else if (k && k.salt === f.salt) key = k.key;
    else throw new CloudError('needpw', 'Dieses Backup wurde mit einem anderen Passwort verschlüsselt. Bitte das Passwort eingeben.');
    let bytes;
    try { bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: B64.dec(f.iv) }, key, B64.dec(f.data))); }
    catch { throw new CloudError('input', 'Passwort falsch oder Backup beschädigt.'); }
    if (f.gz) bytes = await gz(bytes, 'd');
    const data = JSON.parse(new TextDecoder().decode(bytes));
    if (data.format !== 'mm-data') throw new CloudError('input', 'Backup-Inhalt unbekannt.');
    return data;
  },
};

// ---------------- Synchronisierung ----------------
const Cloud = {
  state: 'off', busy: false, again: false, timer: null, listeners: new Set(), changedSinceExport: true, fetching: new Map(),
  st: Object.assign({ lastSyncAt: 0, lastBackupAt: 0, lastBackupName: '', lastSafetyAt: 0, lastBackupCheck: 0, lastExportAt: 0, lastInfoAt: 0, errors: [], devices: [], pushedAt: {}, exportHash: {}, conflictsSeen: 0, backupKeyState: '' }, LS.get('mm-cloud-state', {})),
  dirty: LS.get('mm-dirty', {}),
  ctags: LS.get('mm-ctags', {}),
  done: LS.get('mm-structure', {}),
  renames: LS.get('mm-renames', []),
  saveState() { LS.set('mm-cloud-state', this.st); LS.set('mm-dirty', this.dirty); LS.set('mm-ctags', this.ctags); LS.set('mm-structure', this.done); LS.set('mm-renames', this.renames); },
  on(fn) { this.listeners.add(fn); },
  emit() { for (const fn of this.listeners) { try { fn(this.state); } catch {} } },
  setState(s) { if (this.state !== s) { this.state = s; this.emit(); } },
  connected() { return Auth.configured() && Auth.signedIn(); },
  pending() {
    let n = 0; const me = Device.id;
    for (const r of S.recs.values()) if (r.by === me && !LOCAL_TABLES.has(r.tbl) && r.updatedAt > (this.st.pushedAt[r.tbl] || 0)) n++;
    return n;
  },
  uploadsPending() { return S.list('media').filter((m) => !m.remote && m.blobId && (!m.origin || m.origin === Device.id)).length; },

  /** Wird von S bei jeder lokalen Änderung aufgerufen. */
  onLocalChange(rec, prev) {
    if (LOCAL_TABLES.has(rec.tbl)) return;
    this.dirty[rec.tbl] = (this.dirty[rec.tbl] || 0) + 1;
    this.changedSinceExport = true;
    if (rec.tbl === 'animals' && prev && !prev.deleted && prev.data?.name && rec.data?.name && prev.data.name !== rec.data.name) {
      const from = animalFolder({ ...prev.data }), to = animalFolder({ ...rec.data });
      if (from !== to) this.renames.push({ from, to: to.split('/').pop() });
    }
    LS.set('mm-dirty', this.dirty); LS.set('mm-renames', this.renames);
    try { window.updateSyncPill?.(); } catch {}
    this.schedule(1500);
  },
  markAllDirty() { for (const r of S.recs.values()) if (!LOCAL_TABLES.has(r.tbl) && r.by === Device.id) this.dirty[r.tbl] = (this.dirty[r.tbl] || 0) + 1; this.st.pushedAt = {}; this.saveState(); },
  schedule(ms = 0) { clearTimeout(this.timer); this.timer = setTimeout(() => this.cycle(), ms); },

  /** Einen entfernten Datensatz einarbeiten. Gibt 1 zurück, wenn sich lokal etwas geändert hat. */
  async merge(r) {
    if (!r || !r.tbl || !r.id || r.key !== r.tbl + ':' + r.id || LOCAL_TABLES.has(r.tbl) || typeof r.vv !== 'object') return 0;
    const local = S.recs.get(r.key);
    if (!local) { await S.putRaw(r); return 1; }
    const cmp = vvCompare(r.vv, local.vv);
    if (cmp === 'gt') { await S.putRaw(r); return 1; }
    if (cmp !== 'concurrent') return 0;
    const remoteWins = (r.updatedAt || 0) > (local.updatedAt || 0) || ((r.updatedAt || 0) === (local.updatedAt || 0) && String(r.by) > String(local.by));
    const win = remoteWins ? r : local, lose = remoteWins ? local : r;
    const merged = { ...win, data: { ...win.data }, vv: vvMax(r.vv, local.vv) };
    if (r.tbl === 'media' && !merged.data.remote && lose.data?.remote) merged.data.remote = lose.data.remote;
    await S.putRaw(merged);
    const strip = (d) => { const { remote, ...x } = d || {}; return JSON.stringify(x); };
    const differs = !!win.deleted !== !!lose.deleted || strip(win.data) !== strip(lose.data);
    if (differs && !SILENT_TABLES.has(r.tbl) && !(win.deleted && lose.deleted)) {
      await S.save('conflicts', { tbl: r.tbl, recId: r.id, at: Date.now(), keptBy: win.by, keptAt: win.updatedAt, keptDeleted: !!win.deleted, lostBy: lose.by, lostAt: lose.updatedAt, lostDeleted: !!lose.deleted, lost: lose.data, resolved: false });
    }
    return remoteWins ? 1 : 0;
  },

  async ensureStructure() {
    const oid = Auth.account()?.oid || 'x';
    if (!this.done[oid]) this.done[oid] = { root: false, animals: [] };
    const d = this.done[oid];
    if (!d.root) {
      await G.req('GET', ap('')); // legt den App-Ordner an, falls er fehlt
      for (const f of ROOT_FOLDERS) await G.mkdir('', f);
      await G.put('LIESMICH.txt', new Blob([README_TEXT], { type: 'text/plain;charset=utf-8' }));
      await G.put('Smart-Home-Daten/LIESMICH.txt', new Blob(['Hier speichert die App später automatisch die Messwerte Ihres Smart-Home-Thermometers (über den Raspberry Pi).\nZurzeit von Hand erfasste Häuschen-Werte finden Sie unter «Temperaturverläufe».\n'], { type: 'text/plain;charset=utf-8' }));
      d.root = true; this.saveState();
    }
    for (const a of S.list('animals')) {
      const folder = animalFolder(a); if (d.animals.includes(folder)) continue;
      if (this.renames.some((r) => (dirOf(r.from) + '/' + r.to) === folder)) continue; // wird gleich durch Umbenennen erzeugt
      if (S.recs.get('animals:' + a.id)?.by !== Device.id) continue; // Ordner legt das Gerät an, das das Tier zuletzt bearbeitet hat
      const name = folder.split('/').pop();
      await G.mkdir('Meerschweinchen', name);
      for (const sub of PIG_FOLDERS) await G.mkdir(folder, sub);
      d.animals.push(folder); this.saveState();
    }
  },
  async runRenames() {
    const oid = Auth.account()?.oid || 'x';
    while (this.renames.length) {
      const r = this.renames[0];
      await G.rename(r.from, r.to);
      const d = this.done[oid]; if (d) d.animals = d.animals.filter((x) => x !== r.from);
      this.renames.shift(); this.saveState();
    }
  },
  async push() {
    for (const tbl of Object.keys(this.dirty)) {
      const gen = this.dirty[tbl], startedAt = Date.now();
      const recs = [...S.recs.values()].filter((r) => r.tbl === tbl && r.by === Device.id);
      await G.put(`${SYNC_DIR}/${Device.id}/${safeName(tbl)}.json`, JSON.stringify({ format: 'mm-sync', v: 1, device: Device.id, deviceName: Device.name, tbl, writtenAt: new Date().toISOString(), recs }));
      if (this.dirty[tbl] === gen) delete this.dirty[tbl];
      this.st.pushedAt[tbl] = startedAt;
      this.saveState();
    }
  },
  async pull() {
    let changed = 0;
    const devs = (await G.listOrEmpty(SYNC_DIR)).filter((x) => x.folder);
    const devices = [];
    for (const d of devs) {
      const files = await G.listOrEmpty(`${SYNC_DIR}/${d.name}`);
      const last = files.reduce((m, f) => (String(f.lastModifiedDateTime) > m ? String(f.lastModifiedDateTime) : m), '');
      const prev = this.st.devices.find((x) => x.id === d.name) || {};
      const dev = { id: d.name, name: prev.name || (d.name === Device.id ? Device.name : 'Gerät'), lastSeen: last ? Date.parse(last) : 0, me: d.name === Device.id };
      const info = files.find((f) => f.name === 'geraet.json');
      if (d.name === Device.id) dev.name = Device.name;
      else if (info && this.ctags[d.name + '/geraet.json'] !== (info.cTag || info.eTag)) {
        try { const j = await (await G.download(info)).json(); dev.name = safeName(j.name || 'Gerät', 40); dev.lastSeen = Date.parse(j.lastSeen) || dev.lastSeen; this.ctags[d.name + '/geraet.json'] = info.cTag || info.eTag; } catch {}
      }
      devices.push(dev);
      if (d.name === Device.id) continue;
      for (const f of files) {
        if (!f.file || !f.name.endsWith('.json') || f.name === 'geraet.json') continue;
        const k = d.name + '/' + f.name, tag = f.cTag || f.eTag;
        if (this.ctags[k] === tag) continue;
        let j; try { j = await (await G.download(f)).json(); } catch (e) { if (e instanceof CloudError) throw e; continue; }
        if (j && j.format === 'mm-sync' && Array.isArray(j.recs)) for (const r of j.recs) changed += await this.merge(r);
        this.ctags[k] = tag; this.saveState();
      }
    }
    if (!devices.some((x) => x.me)) devices.push({ id: Device.id, name: Device.name, lastSeen: Date.now(), me: true });
    this.st.devices = devices;
    if (changed) { this.changedSinceExport = true; try { window.onCloudData?.(changed); } catch {} }
    return changed;
  },
  async uploadMedia(budget = 25000) {
    const t0 = Date.now();
    for (const m of S.list('media')) {
      if (m.remote || !m.blobId || (m.origin && m.origin !== Device.id)) continue;
      const blob = await S.getBlob(m.blobId); if (!blob) continue;
      const path = mediaPath(m);
      const it = await G.put(path, blob, { rename: true });
      const cur = S.get('media', m.id); if (!cur || !it) continue;
      await S.save('media', { ...cur, remote: { id: it.id, name: it.name, path: dirOf(path) + '/' + it.name, size: it.size } });
      if (Date.now() - t0 > budget) { this.again = true; break; }
    }
  },
  async fetchBlob(m) {
    if (!m?.remote?.id || !this.connected() || Auth.needsLogin || navigator.onLine === false) return null;
    if (this.fetching.has(m.blobId)) return this.fetching.get(m.blobId);
    const p = (async () => {
      try { const res = await G.download({ id: m.remote.id }); const b = await res.blob(); const blob = new Blob([b], { type: m.mime || b.type }); await S.putBlob(m.blobId, blob); return blob; }
      catch { return null; } finally { this.fetching.delete(m.blobId); }
    })();
    this.fetching.set(m.blobId, p); return p;
  },
  async deviceInfo(force) {
    if (!force && Date.now() - this.st.lastInfoAt < 10 * 60000) return;
    await G.put(`${SYNC_DIR}/${Device.id}/geraet.json`, JSON.stringify({ format: 'mm-device', id: Device.id, name: Device.name, lastSeen: new Date().toISOString(), app: APP_VERSION, standalone: !!(window.matchMedia?.('(display-mode: standalone)').matches || navigator.standalone) }));
    this.st.lastInfoAt = Date.now();
  },
  async exports(force) {
    if (typeof window.readableExports !== 'function') return;
    if (!force && (!this.changedSinceExport || Date.now() - this.st.lastExportAt < 10 * 60000)) return;
    for (const f of window.readableExports()) {
      const h = await sha256(f.path + '\n' + f.text);
      if (this.st.exportHash[f.path] === h) continue;
      await G.put(f.path, new Blob([f.bom === false ? '' : '﻿', f.text], { type: f.type || 'text/csv;charset=utf-8' }));
      this.st.exportHash[f.path] = h; this.saveState();
    }
    this.st.lastExportAt = Date.now(); this.changedSinceExport = false;
  },
  async autoBackup(force) {
    if (!force && Date.now() - this.st.lastBackupCheck < 60 * 60000) return;
    this.st.lastBackupCheck = Date.now();
    const ks = await Backup.status(); this.st.backupKeyState = ks;
    const list = (await G.listOrEmpty(BACKUP_DIR)).filter((f) => f.file && /^Backup .*\.json$/.test(f.name)).sort((a, b) => String(b.createdDateTime).localeCompare(String(a.createdDateTime)));
    const newest = list[0] ? Date.parse(list[0].createdDateTime) : 0;
    if (newest) { this.st.lastBackupAt = Math.max(this.st.lastBackupAt || 0, newest); this.st.lastBackupName = this.st.lastBackupName || list[0].name; }
    if (ks !== 'ready') return;
    const changes = [...S.recs.values()].some((r) => !LOCAL_TABLES.has(r.tbl) && r.updatedAt > newest);
    const age = Date.now() - newest;
    if ((age > 24 * 3600000 && changes) || age > 7 * 24 * 3600000) await Backup.create('automatisch');
  },
  /** Sicherung vor grösseren Änderungen. Gibt true zurück, wenn gesichert wurde. */
  async safetyBackup(reason) {
    if (!this.connected() || Auth.needsLogin || navigator.onLine === false) return false;
    if ((await Backup.status()) !== 'ready') return false;
    for (let i = 0; this.busy && i < 150; i++) await sleep(200); // laufenden Abgleich abwarten
    await this.push();
    await Backup.create(reason, APPBACKUP_DIR);
    return true;
  },
  fail(e) {
    const code = e?.code;
    if (code === 'login' || code === 'signedout') { Auth.needsLogin = Auth.signedIn(); this.setState(Auth.signedIn() ? 'needs-login' : 'signedout'); }
    else if (code === 'offline' || code === 'network') this.setState('offline');
    else this.setState('error');
    if (code !== 'offline') {
      const msg = e?.message || String(e);
      const last = this.st.errors[0];
      if (!last || last.msg !== msg || Date.now() - last.at > 10 * 60000) {
        this.st.errors.unshift({ at: Date.now(), msg }); this.st.errors = this.st.errors.slice(0, 12);
        if (code !== 'login' && code !== 'network') try { window.toast?.('Synchronisierung: ' + msg); } catch {}
      }
    }
  },
  /** Ein vollständiger Abgleich. */
  async cycle(opts = {}) {
    if (!Auth.configured()) return this.setState('unconfigured');
    if (!Auth.signedIn()) return this.setState('signedout');
    if (Auth.needsLogin) return this.setState('needs-login');
    if (navigator.onLine === false) return this.setState('offline');
    if (this.busy) { this.again = true; return; }
    this.busy = true; this.again = false; this.setState('syncing');
    let ok = false;
    try {
      await this.runRenames();
      await this.push();
      await this.pull();
      await this.ensureStructure();
      await this.uploadMedia();
      if (Object.keys(this.dirty).length) await this.push();
      await this.deviceInfo(opts.full);
      await this.exports(opts.full);
      await this.autoBackup(opts.full);
      this.st.lastSyncAt = Date.now(); ok = true;
      this.st.errors = []; // erfolgreicher Abgleich: frühere Fehler sind behoben
      this.setState('ok');
    } catch (e) { this.fail(e); }
    finally {
      this.busy = false; this.saveState(); this.emit();
      if (ok && (this.again || Object.keys(this.dirty).length)) this.schedule(400);
    }
  },
  async syncNow() {
    for (let i = 0; this.busy && i < 300; i++) await sleep(150); // laufenden Abgleich abwarten, dann vollständig abgleichen
    this.st.lastBackupCheck = 0; await this.cycle({ full: true }); return this.state;
  },
  async connect() { this.st.lastBackupCheck = 0; this.saveState(); return Auth.login({}); },
  async disconnect() { await Auth.logout(); await Backup.forget(); this.setState('signedout'); this.emit(); },
  async browse(path) { return (await G.listOrEmpty(path)).sort((a, b) => (!!b.folder - !!a.folder) || a.name.localeCompare(b.name, 'de')); },
  async openItem(item) { const res = await G.download(item); return res.blob(); },

  async init() {
    let result = null;
    try { result = await Auth.handleRedirect(); } catch (e) { result = { error: e.message }; }
    if (result?.ok) {
      if (result.switched) { this.ctags = {}; this.st.devices = []; }
      this.markAllDirty(); this.changedSinceExport = true; this.st.lastBackupCheck = 0;
    }
    if (result?.error) Auth.lastError = result.error;
    window.addEventListener('online', () => this.schedule(200));
    window.addEventListener('offline', () => this.setState('offline'));
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') this.schedule(300); });
    setInterval(() => { if (document.visibilityState === 'visible' && !this.busy) this.cycle(); }, 30000);
    // Abgelaufene Anmeldung beim Start still erneuern (kurzer Sprung zu Microsoft, meist ohne Eingabe).
    if (this.connected() && navigator.onLine !== false && !result) {
      try { await Auth.token(); }
      catch (e) {
        if (e.code === 'login' && LS.get('mm-autorenew', true) !== false && Date.now() - LS.get('mm-silent-at', 0) > 10 * 60000 && !this.userActed) {
          LS.set('mm-silent-at', Date.now()); return Auth.login({ silent: true });
        }
      }
    }
    this.schedule(result?.ok ? 50 : 600);
    return result;
  },
  userActed: false,
};
['pointerdown', 'keydown'].forEach((ev) => document.addEventListener(ev, () => { Cloud.userActed = true; }, { once: true, capture: true }));

const README_TEXT = `Meine Meerschweinchen – Ordner in OneDrive
==========================================

Diesen Ordner verwaltet die App «Meine Meerschweinchen» automatisch.

Datenbank-Backups/   Automatische, verschlüsselte Backups (täglich, wenn sich etwas geändert hat).
App-Backups/         Backups vor grösseren Änderungen (z. B. vor einer Wiederherstellung) und von Hand erstellte.
Meerschweinchen/     Pro Tier ein Ordner mit Fotos, Tierarzt-Dokumenten und lesbaren Tabellen (CSV, für Excel).
Kassenzettel/        Fotos Ihrer Belege und eine Kostenübersicht.
PDF-Berichte/        Exportierte Gesundheitsakten und Tierarztberichte.
Temperaturverläufe/  Häuschen-Klima als Tabelle.
Wetterdaten/         Tägliches Wetterprotokoll.
Smart-Home-Daten/    Für spätere automatische Sensordaten.
Synchronisierung/    Technische Daten für den Abgleich zwischen Ihren Geräten. Bitte nicht verändern oder löschen.

Die CSV-Tabellen werden von der App neu geschrieben. Änderungen daran fliessen nicht in die App zurück.
`;

window.Cloud = Cloud; window.Auth = Auth; window.Backup = Backup; window.Device = Device; window.CloudError = CloudError;
window.mediaPath = mediaPath; window.vvCompare = vvCompare; window.LOCAL_TABLES = LOCAL_TABLES;
