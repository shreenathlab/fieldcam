/* FieldCam 2 — job-based testing photos & videos straight to the QNAP NAS.
 *
 * Flow: Jobs list → pick a job → Laboratory or Field → camera (photo / video).
 * Every photo/video is stamped according to its type, split into small pieces,
 * encrypted and queued inside the app (never the gallery), uploaded piece by
 * piece, and deleted from the phone as soon as the NAS confirms it is saved.
 */
'use strict';

const APP_VERSION = '4.3.4';
/* Server: the Google Apps Script web app (config.js `api`, files go to Google Drive), or the PHP
   API next to the page on the NAS / the saved NAS address in an installed app. */
const GAS_URL = (window.FIELDCAM_CONFIG?.api || '').trim();
const STORE = GAS_URL ? 'Google Drive' : 'NAS';
const STORE_THE = GAS_URL ? 'Google Drive' : 'the NAS';     // "reached Google Drive" / "reached the NAS"
const IS_NATIVE = !GAS_URL && !!(window.Capacitor?.isNativePlatform?.() || window.FIELDCAM_CONFIG?.native);
/* Bridge from the Android WebView app (android/), which loads this page from the web. */
const ANDROID_APP = window.FieldCamAndroid || null;
let nasUrl = (window.FIELDCAM_CONFIG?.server || '').trim();
function apiUrl(path) {
  if (!nasUrl) return 'api/' + path;
  return nasUrl.replace(/\/+$/, '') + '/api/' + path;
}
// Google Drive needs pieces in multiples of 256 KB; the NAS's default PHP upload limit needs them small.
const CHUNK = (GAS_URL ? 5 : 1.5) * 1024 * 1024;   // bigger pieces = fewer round trips to Google (faster)
const MAX_VIDEO_SEC = 30 * 60;
const $ = (id) => document.getElementById(id);

const LAB_ITEMS = [['job_number', 'Sub-Job No.'], ['site_name', 'Project name'], ['test_name', 'Test name'], ['datetime', 'Date & time']];
const FIELD_ITEMS = [['logo', 'Company logo'], ['datetime', 'Date & time'], ['coords', 'Coordinates'], ['location_name', 'Site location'], ['site_name', 'Project name'], ['test_name', 'Field test name'], ['custom_text', 'Your text']];
const COORD_FORMATS = [['decimal', 'Decimal degrees'], ['dms', 'Deg° Min′ Sec″'], ['ddm', 'Deg° Decimal-min′'], ['utm', 'UTM']];
const TEXT_SIZES = [['small', 'Small'], ['large', 'Large'], ['xlarge', 'Extra large']];
const BANDS = [['strip', 'Strip (full width)'], ['box', 'Box (fits the text)'], ['none', 'None (outlined text)']];
const BG_SWATCHES = ['#000000', '#ffffff', '#1f2f6b', '#5a5a5a'];
const SWATCHES = ['#ffffff', '#ffd400', '#ff3b30', '#34c759', '#00b7ff', '#000000'];
const STAMP_FONT = '"Roboto Condensed", "Arial Narrow", sans-serif';
const CORNERS = [['top-left', 'Top left'], ['top-right', 'Top right'], ['bottom-left', 'Bottom left'], ['bottom-right', 'Bottom right']];

const state = {
  auth: null,                 // {token, user, name, role}
  jobs: [],
  settings: null,             // company settings from the NAS
  server: {},                 // storage status
  jobDetails: {},             // per job: {test_name (lab), field_test, custom_text}
  job: null, type: 'Field', mode: 'photo',
  gps: null, gpsWatch: null,
  stream: null, track: null, imageCapture: null, facing: 'environment', torch: false, streamMode: null,
  logo: null, logoVersion: 0,
  pending: null, busy: false, syncing: false,
  rec: null,                  // active video recording
  editingJob: null,
};

/* ======================= storage (app-private IndexedDB) ======================= */
let dbp;
function db() {
  if (!dbp) dbp = new Promise((res, rej) => {
    const r = indexedDB.open('fieldcam', 2);
    r.onupgradeneeded = (e) => {
      const d = r.result;
      if (!d.objectStoreNames.contains('kv')) d.createObjectStore('kv');
      if (e.oldVersion < 2 && d.objectStoreNames.contains('queue')) d.deleteObjectStore('queue');
      if (!d.objectStoreNames.contains('queue')) d.createObjectStore('queue', { keyPath: 'uid' });
      if (!d.objectStoreNames.contains('chunks')) d.createObjectStore('chunks');
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  return dbp;
}
async function tx(store, mode, fn) {
  const d = await db();
  return new Promise((res, rej) => {
    const t = d.transaction(store, mode);
    const out = fn(t.objectStore(store));
    t.oncomplete = () => res(out && 'result' in out ? out.result : undefined);
    t.onerror = () => rej(t.error);
    t.onabort = () => rej(t.error || new Error('Phone storage is full'));
  });
}
const kvGet = (k) => tx('kv', 'readonly', (s) => s.get(k));
const kvSet = (k, v) => tx('kv', 'readwrite', (s) => s.put(v, k));
const kvDel = (k) => tx('kv', 'readwrite', (s) => s.delete(k));
const qAll = () => tx('queue', 'readonly', (s) => s.getAll());
const qPut = (r) => tx('queue', 'readwrite', (s) => s.put(r));
const chunkKey = (uid, i) => `${uid}#${String(i).padStart(5, '0')}`;
const chunkPut = (uid, i, v) => tx('chunks', 'readwrite', (s) => s.put(v, chunkKey(uid, i)));
const chunkGet = (uid, i) => tx('chunks', 'readonly', (s) => s.get(chunkKey(uid, i)));
async function qRemove(uid) {
  const d = await db();
  return new Promise((res, rej) => {
    const t = d.transaction(['queue', 'chunks'], 'readwrite');
    t.objectStore('queue').delete(uid);
    t.objectStore('chunks').delete(IDBKeyRange.bound(uid + '#', uid + '#￿'));
    t.oncomplete = res; t.onerror = () => rej(t.error);
  });
}

/* ======================= encryption of queued pieces ======================= */
let keyP;
function getKey() {
  if (!keyP) keyP = (async () => {
    if (!crypto.subtle) return null;
    try {
      let k = await kvGet('aesKey');
      if (!k) {
        k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        await kvSet('aesKey', k);
      }
      return k;
    } catch (e) { console.warn('Encryption unavailable', e); return null; }
  })();
  return keyP;
}
async function seal(buf) {
  const key = await getKey();
  if (!key) return { enc: false, data: buf };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { enc: true, iv, data: await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf) };
}
async function unseal(c) {
  return c.enc ? crypto.subtle.decrypt({ name: 'AES-GCM', iv: c.iv }, await getKey(), c.data) : c.data;
}

/* ======================= helpers ======================= */
function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
let toastT;
function toast(msg, bad = false, ms = 2800) {
  const t = $('toast');
  t.textContent = msg; t.classList.toggle('bad', bad); t.classList.add('show');
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), ms);
}
function toB64(buf) {
  const u = new Uint8Array(buf); let s = '';
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(b) {
  const s = atob(b), u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u.buffer;
}
/* Google Apps Script: one address, every call is a POST of plain-text JSON (no custom headers, so the
   browser sends no CORS preflight). The token and any files (base64) travel inside the body, and the
   real HTTP status comes back inside the reply because Apps Script always answers 200. */
const GAS_OPS = { 'login.php': 'login', 'bootstrap.php': 'bootstrap', 'logo.php': 'logo', 'admin.php': 'admin', 'upload.php': 'upload', 'job.php': 'job' };
async function gasApi(path, { body, json, raw }, signal) {
  const o = { op: GAS_OPS[path], token: state.auth?.token || '' };
  if (json) Object.assign(o, json);
  if (body instanceof FormData) {
    for (const [k, v] of body) o[k] = v instanceof Blob ? { b64: toB64(await v.arrayBuffer()), type: v.type } : v;
  }
  const r = await fetch(GAS_URL, {
    method: 'POST', body: JSON.stringify(o), headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    signal, cache: 'no-store', redirect: 'follow',
  });
  let data;
  try { data = await r.json(); } catch { data = { ok: false, status: 502, error: 'Google server gave an unexpected reply — check the web app deployment (Who has access: Anyone)' }; }
  const status = data.status || r.status;
  if (status === 401 && state.auth) sessionExpired();
  if (raw) return { ok: !!data.ok, status, arrayBuffer: async () => fromB64(data.b64 || '') };
  return { ...data, status };
}
async function api(path, { body, json, timeout = 30000, raw = false } = {}) {
  const ctl = new AbortController();
  const tm = setTimeout(() => ctl.abort(), timeout);
  if (GAS_URL) {
    try { return await gasApi(path, { body, json, raw }, ctl.signal); }
    catch (e) { return { status: 0, ok: false, error: e.name === 'AbortError' ? 'Timed out' : 'No connection to Google Drive' }; }
    finally { clearTimeout(tm); }
  }
  const headers = {};
  if (state.auth) headers['X-FieldCam-Token'] = state.auth.token;
  if (json) headers['Content-Type'] = 'application/json';
  try {
    const r = await fetch(apiUrl(path), {
      method: body || json ? 'POST' : 'GET', headers, body: json ? JSON.stringify(json) : body,
      signal: ctl.signal, cache: 'no-store', credentials: 'same-origin',
    });
    if (raw) return r;
    let data;
    try { data = await r.json(); } catch { data = { ok: false, error: `NAS replied ${r.status} (is PHP enabled?)` }; }
    if (r.status === 401 && state.auth) sessionExpired();
    return { status: r.status, ...data };
  } catch (e) {
    return { status: 0, ok: false, error: e.name === 'AbortError' ? 'Timed out' : 'No connection to NAS' };
  } finally { clearTimeout(tm); }
}
const pad2 = (n) => String(n).padStart(2, '0');
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
/** Stamp date & time, e.g. "27 September, 2026 | 04:30 PM" (12-hour, hh:mm). */
function fmtDate(d) {
  const h = d.getHours() % 12 || 12;
  return `${d.getDate()} ${MONTHS[d.getMonth()]}, ${d.getFullYear()} | ${pad2(h)}:${pad2(d.getMinutes())} ${d.getHours() < 12 ? 'AM' : 'PM'}`;
}
function fmtBytes(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.round(n / 1024) + ' KB'; }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function distM(a, b) {
  const R = 6371000, r = Math.PI / 180;
  const x = (b.lon - a.lon) * r * Math.cos(((a.lat + b.lat) / 2) * r), y = (b.lat - a.lat) * r;
  return Math.hypot(x, y) * R;
}

/* ======================= coordinates ======================= */
function toUTM(lat, lon) {
  const a = 6378137, f = 1 / 298.257223563, k0 = 0.9996;
  const e2 = f * (2 - f), ep2 = e2 / (1 - e2);
  let zone = Math.floor((lon + 180) / 6) + 1;
  if (lat >= 56 && lat < 64 && lon >= 3 && lon < 12) zone = 32;             // Norway
  if (lat >= 72 && lat < 84) { if (lon >= 0 && lon < 9) zone = 31; else if (lon >= 9 && lon < 21) zone = 33; else if (lon >= 21 && lon < 33) zone = 35; else if (lon >= 33 && lon < 42) zone = 37; }
  const r = Math.PI / 180, phi = lat * r, lam = lon * r, lam0 = ((zone - 1) * 6 - 180 + 3) * r;
  const s = Math.sin(phi), c = Math.cos(phi), t = Math.tan(phi);
  const N = a / Math.sqrt(1 - e2 * s * s), T = t * t, C = ep2 * c * c, A = c * (lam - lam0);
  const M = a * ((1 - e2 / 4 - 3 * e2 ** 2 / 64 - 5 * e2 ** 3 / 256) * phi
    - (3 * e2 / 8 + 3 * e2 ** 2 / 32 + 45 * e2 ** 3 / 1024) * Math.sin(2 * phi)
    + (15 * e2 ** 2 / 256 + 45 * e2 ** 3 / 1024) * Math.sin(4 * phi)
    - (35 * e2 ** 3 / 3072) * Math.sin(6 * phi));
  const E = k0 * N * (A + (1 - T + C) * A ** 3 / 6 + (5 - 18 * T + T * T + 72 * C - 58 * ep2) * A ** 5 / 120) + 500000;
  let Nn = k0 * (M + N * t * (A * A / 2 + (5 - T + 9 * C + 4 * C * C) * A ** 4 / 24 + (61 - 58 * T + T * T + 600 * C - 330 * ep2) * A ** 6 / 720));
  if (lat < 0) Nn += 10000000;
  const band = 'CDEFGHJKLMNPQRSTUVWXX'[Math.max(0, Math.min(20, Math.floor((lat + 80) / 8)))];
  return { zone, band, E, N: Nn };
}
/** UTM (WGS 84) → latitude/longitude, for coordinates typed in as UTM. */
function fromUTM(zone, band, E, N) {
  const a = 6378137, f = 1 / 298.257223563, k0 = 0.9996, e2 = f * (2 - f), ep2 = e2 / (1 - e2);
  const north = band.toUpperCase() >= 'N';
  const x = E - 500000, y = north ? N : N - 10000000;
  const mu = y / k0 / (a * (1 - e2 / 4 - 3 * e2 ** 2 / 64 - 5 * e2 ** 3 / 256));
  const e1 = (1 - Math.sqrt(1 - e2)) / (1 + Math.sqrt(1 - e2));
  const p1 = mu + (3 * e1 / 2 - 27 * e1 ** 3 / 32) * Math.sin(2 * mu) + (21 * e1 ** 2 / 16 - 55 * e1 ** 4 / 32) * Math.sin(4 * mu)
    + (151 * e1 ** 3 / 96) * Math.sin(6 * mu) + (1097 * e1 ** 4 / 512) * Math.sin(8 * mu);
  const s = Math.sin(p1), c = Math.cos(p1), t = Math.tan(p1);
  const N1 = a / Math.sqrt(1 - e2 * s * s), T1 = t * t, C1 = ep2 * c * c, R1 = a * (1 - e2) / Math.pow(1 - e2 * s * s, 1.5), D = x / (N1 * k0);
  const lat = p1 - (N1 * t / R1) * (D * D / 2 - (5 + 3 * T1 + 10 * C1 - 4 * C1 * C1 - 9 * ep2) * D ** 4 / 24
    + (61 + 90 * T1 + 298 * C1 + 45 * T1 * T1 - 252 * ep2 - 3 * C1 * C1) * D ** 6 / 720);
  const lon = ((zone - 1) * 6 - 180 + 3) * Math.PI / 180
    + (D - (1 + 2 * T1 + C1) * D ** 3 / 6 + (5 - 2 * C1 + 28 * T1 - 3 * C1 * C1 + 8 * ep2 + 24 * T1 * T1) * D ** 5 / 120) / c;
  return { lat: lat * 180 / Math.PI, lon: lon * 180 / Math.PI };
}
function fmtCoords(lat, lon, fmt) {
  const ns = lat >= 0 ? 'N' : 'S', ew = lon >= 0 ? 'E' : 'W';
  const la = Math.abs(lat), lo = Math.abs(lon);
  const dms = (v) => {
    let d = Math.floor(v), m = Math.floor((v - d) * 60), s = ((v - d) * 60 - m) * 60;
    if (s >= 59.995) { s = 0; m += 1; } if (m >= 60) { m = 0; d += 1; }
    return `${d}°${pad2(m)}′${s.toFixed(2).padStart(5, '0')}″`;
  };
  const ddm = (v) => { const d = Math.floor(v); return `${d}°${((v - d) * 60).toFixed(4).padStart(7, '0')}′`; };
  switch (fmt) {
    case 'dms': return `${dms(la)} ${ns}, ${dms(lo)} ${ew}`;
    case 'ddm': return `${ddm(la)} ${ns}, ${ddm(lo)} ${ew}`;
    case 'utm': {
      if (lat < -80 || lat > 84) return fmtCoords(lat, lon, 'decimal');
      const u = toUTM(lat, lon);
      // whole metres, e.g. "42 Q 759213 m E 2360761 m N" (no "UTM" label on the photo)
      return `${u.zone} ${u.band} ${Math.round(u.E)} m E ${Math.round(u.N)} m N`;
    }
    default: return `${la.toFixed(6)}° ${ns}, ${lo.toFixed(6)}° ${ew}`;
  }
}

/* ======================= stamps ======================= */
/** Company photo settings (set by admins only). */
function photoConf() {
  return { max_dim: 0, quality: 0.92, review: true, aspect: '', ...(state.settings?.photo || {}) };
}
function stampConf(type) {
  const s = state.settings || {};
  const base = { ...(type === 'Laboratory' ? s.lab : s.field) };
  return base;
}
function currentDetails() {
  const id = state.job?.id;
  if (!state.jobDetails[id]) state.jobDetails[id] = { test_name: '', field_test: '', custom_text: '' };
  if (state.jobDetails[id].field_test === undefined) state.jobDetails[id].field_test = '';
  return state.jobDetails[id];
}
function locationName() {
  return state.job?.location_name || '';
}
/** Everything that goes onto the photo, as plain text lines + logo placement. */
function buildStamp(type, when, gps, ov) {
  // ov (uploaded photos): { details, coordText } typed in by the user instead of this phone's camera details/GPS
  const c = stampConf(type), job = state.job, d = ov?.details || currentDetails(), lines = [];
  let coordText = '';
  if (ov && ov.coordText !== undefined) coordText = ov.coordText;
  else if (gps) coordText = fmtCoords(gps.lat, gps.lon, c.coord_format || 'utm');
  if (type === 'Laboratory') {
    if (c.job_number) lines.push(`Sub-Job No: ${job.job_number}`);
    if (c.site_name) lines.push(`Project: ${job.site_name}`);
    if (c.test_name && d.test_name) lines.push(`Test: ${d.test_name}`);
    if (c.datetime) lines.push(fmtDate(when));
    return { lines, logo: false, coordText, style: stampStyle(c) };
  }
  if (c.datetime) lines.push(fmtDate(when));
  if (c.coords) lines.push(coordText || 'Coordinates: not available');
  if (c.location_name && locationName()) lines.push(locationName());
  if (c.site_name) lines.push(`Project: ${job.site_name}`);
  if (c.test_name && d.field_test) lines.push(`Test: ${d.field_test}`);
  if (c.custom_text && d.custom_text) lines.push(d.custom_text);
  return { lines, logo: !!(c.logo && state.logo), corner: c.logo_corner || 'top-left', logoSize: c.logo_size, logoOpacity: c.logo_opacity, coordText, style: stampStyle(c) };
}
/* ---------- stamp style ---------- */
const SIZE_FACTOR = { small: 0.026, large: 0.036, xlarge: 0.048 };
const MAX_LINES_PER_COLUMN = 3;
/** Normalise a stamp config (also upgrades the old "dark"/"light" strip settings). */
function stampStyle(c) {
  const hex = (v, d) => (/^#[0-9a-f]{6}$/i.test(v || '') ? v : d);
  let band = c.band || 'strip', bg = c.bg_color, op = c.bg_opacity;
  if (band === 'dark') { band = 'strip'; bg = bg || '#000000'; op = op ?? 55; }
  if (band === 'light') { band = 'strip'; bg = bg || '#ffffff'; op = op ?? 65; }
  const opacity = Math.max(0, Math.min(100, Number(op ?? 55)));
  return { color: hex(c.text_color, '#ffffff'), size: SIZE_FACTOR[c.text_size] ? c.text_size : 'large', band: ['strip', 'box', 'none'].includes(band) ? band : 'strip', bg: hex(bg, '#000000'), opacity };
}
function luminance(hex) {
  const n = parseInt(hex.slice(1), 16);
  return (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255;
}
function rgba(hex, opacity) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${opacity / 100})`;
}
function wrapText(ctx, text, maxW) {
  const out = [];
  for (const para of String(text).split(/\n/)) {
    let cur = '';
    for (const w of para.split(/\s+/)) {
      if (!w) continue;
      const test = cur ? cur + ' ' + w : w;
      if (ctx.measureText(test).width <= maxW || !cur) cur = test; else { out.push(cur); cur = w; }
    }
    if (cur) out.push(cur);
  }
  return out;
}
/**
 * Arrange stamp items in at most 2 columns of at most 3 lines each.
 * Up to 3 lines → one column; more → two columns side by side. If it still doesn't fit,
 * the font is reduced step by step. Returns {fs, cols: [[lines...], ...]}.
 */
function layoutStamp(ctx, w, h, items, st, font) {
  let fs = Math.max(9, Math.round(Math.min(w, h) * SIZE_FACTOR[st.size]));
  const minFs = Math.max(8, Math.round(fs * 0.5));
  for (;;) {
    ctx.font = `600 ${fs}px ${font}`;
    const pad = Math.round(fs * 0.7), gap = Math.round(fs * 1.6);
    const avail = st.band === 'box' ? w * 0.94 - pad * 4 : w - pad * 2;   // box keeps a margin from the edge
    for (const nCols of [1, 2]) {
      if (nCols === 1 && items.length > MAX_LINES_PER_COLUMN) continue;
      const colW = nCols === 1 ? avail : (avail - gap) / 2;
      const cols = [[]];
      let ok = true;
      for (const it of items) {
        const wrapped = wrapText(ctx, it, colW);
        if (wrapped.length > MAX_LINES_PER_COLUMN) { ok = false; break; }
        if (cols[cols.length - 1].length + wrapped.length > MAX_LINES_PER_COLUMN) cols.push([]);
        if (cols.length > nCols) { ok = false; break; }
        cols[cols.length - 1].push(...wrapped);
      }
      if (ok) return { fs, pad, gap, cols: cols.filter((c) => c.length) };
    }
    if (fs <= minFs) {                                // last resort: keep what fits
      const colW = (avail - gap) / 2, all = items.flatMap((it) => wrapText(ctx, it, colW));
      return { fs, pad, gap, cols: [all.slice(0, 3), all.slice(3, 6)].filter((c) => c.length) };
    }
    fs = Math.max(minFs, Math.round(fs * 0.9));
  }
}
/**
 * Draws the stamp on an image area of w×h (same routine for the live preview, photos and video frames).
 * Returns the stamped lines in reading order.
 */
function renderStamp(ctx, w, h, stamp, logoImg, font) {
  const st = stamp.style || stampStyle({});
  const base = Math.min(w, h);
  ctx.save();
  ctx.textBaseline = 'top';
  let blockTop = h, out = [];
  if (stamp.lines.length) {
    const L = layoutStamp(ctx, w, h, stamp.lines, st, font);
    const { fs, pad, gap, cols } = L;
    ctx.font = `600 ${fs}px ${font}`;
    const lineH = Math.round(fs * 1.28);
    const rows = Math.max(...cols.map((c) => c.length));
    const textH = rows * lineH - (lineH - fs);
    const colWidths = cols.map((c) => Math.max(...c.map((l) => ctx.measureText(l).width)));
    const contentW = colWidths.reduce((a, b) => a + b, 0) + gap * (cols.length - 1);
    let x0, y0, boxW, boxH = textH + pad * 2;
    if (st.band === 'box') {
      const m = pad;
      boxW = contentW + pad * 2;
      // Portrait photos/videos: centre the box; landscape: bottom-left
      x0 = h > w ? Math.round((w - boxW) / 2) : m; y0 = h - m - boxH;
      if (st.opacity > 0) {
        ctx.fillStyle = rgba(st.bg, st.opacity);
        const r = Math.round(fs * 0.45);
        ctx.beginPath();
        ctx.moveTo(x0 + r, y0); ctx.arcTo(x0 + boxW, y0, x0 + boxW, y0 + boxH, r); ctx.arcTo(x0 + boxW, y0 + boxH, x0, y0 + boxH, r);
        ctx.arcTo(x0, y0 + boxH, x0, y0, r); ctx.arcTo(x0, y0, x0 + boxW, y0, r); ctx.closePath(); ctx.fill();
      }
    } else {
      x0 = 0; y0 = h - boxH; boxW = w;
      if (st.band === 'strip' && st.opacity > 0) { ctx.fillStyle = rgba(st.bg, st.opacity); ctx.fillRect(0, y0, w, boxH); }
    }
    blockTop = y0;
    // Outline the text when the background doesn't give enough contrast
    const needsOutline = st.band === 'none' || st.opacity < 35 || Math.abs(luminance(st.color) - luminance(st.bg)) < 0.45;
    const outline = luminance(st.color) > 0.55 ? 'rgba(0,0,0,0.85)' : 'rgba(255,255,255,0.9)';
    let cx = x0 + pad;
    const colStep = (ci) => (st.band === 'box' ? colWidths[ci] : (w - pad * 2 - gap) / cols.length) + gap;
    // Vertical divider between the two columns
    if (cols.length > 1) {
      const lx = Math.round(cx + colStep(0) - gap / 2);
      ctx.save();
      ctx.strokeStyle = st.color; ctx.globalAlpha = 0.6; ctx.lineWidth = Math.max(1, Math.round(fs * 0.08));
      if (needsOutline) { ctx.shadowColor = outline; ctx.shadowBlur = Math.max(1, fs * 0.15); }
      ctx.beginPath(); ctx.moveTo(lx, y0 + pad * 0.6); ctx.lineTo(lx, y0 + boxH - pad * 0.6); ctx.stroke();
      ctx.restore();
    }
    cols.forEach((col, ci) => {
      col.forEach((l, i) => {
        const y = y0 + pad + i * lineH;
        if (needsOutline) { ctx.lineWidth = Math.max(2, fs * 0.16); ctx.lineJoin = 'round'; ctx.strokeStyle = outline; ctx.strokeText(l, cx, y); }
        ctx.fillStyle = st.color; ctx.fillText(l, cx, y);
      });
      cx += colStep(ci);
      out.push(...col);
    });
  }
  if (stamp.logo && logoImg) {
    const pad = Math.round(base * 0.025);
    // logoSize = logo width as % of the photo's short side (default 26)
    const size = Math.max(5, Math.min(60, Number(stamp.logoSize) || 26)) / 100;
    const sc = Math.min((base * size) / logoImg.width, (base * size * 0.55) / logoImg.height);
    const lw = logoImg.width * sc, lh = logoImg.height * sc;
    const x = stamp.corner.endsWith('right') ? w - lw - pad : pad;
    const y = stamp.corner.startsWith('bottom') ? blockTop - lh - pad : pad;
    ctx.globalAlpha = Math.max(10, Math.min(100, Number(stamp.logoOpacity ?? 100))) / 100;   // logo opacity (admin setting)
    ctx.drawImage(logoImg, x, y, lw, lh);
    ctx.globalAlpha = 1;
  }
  ctx.restore();
  return out;
}
function drawStamp(ctx, w, h, stamp) { return renderStamp(ctx, w, h, stamp, state.logo, STAMP_FONT); }

/* ======================= navigation (works with the phone's Back button) ======================= */
const SCREENS = ['login', 'jobs', 'typePick', 'cam'];
function show(screen) {
  for (const id of SCREENS) $(id).hidden = id !== screen;
  state.screen = screen;
  // Android app: on the camera screen follow the phone's position even when auto-rotate is off
  try { ANDROID_APP?.setCameraMode?.(screen === 'cam'); } catch {}
}
function pushNav() { history.pushState({ fc: Date.now() }, ''); }
function goBack() { history.back(); }
window.addEventListener('popstate', () => {
  if (ddOpen) { closeDropdown(); pushNav(); return; }                            // back button closes a drop-down
  if (!$('confirmDlg').hidden) { $('confirmNo').click(); pushNav(); return; }   // back button = Cancel
  if (!$('review').hidden) { endReview(); return; }
  if (openSheetId) { closeSheetNow(); return; }
  if (state.screen === 'cam') { if (state.rec) { stopRecording(); pushNav(); return; } leaveCamera(); show('typePick'); return; }
  if (state.screen === 'typePick') { state.job = null; show('jobs'); renderJobs(); }
});

let openSheetId = null;
const SHEET_RENDER = {
  detailsSheet: renderDetails, queueSheet: renderQueue,
  settingsSheet: renderSettings, jobSheet: renderJobSheet, adminSheet: renderAdmin, uploadSheet: renderUpload,
};
function openSheet(id) {
  if (openSheetId) { $(openSheetId).hidden = true; if (openSheetId === 'queueSheet') revokeThumbs(); }
  else pushNav();
  openSheetId = id; $(id).hidden = false; $('scrim').hidden = false;
  SHEET_RENDER[id]?.();
}
function closeSheet() { if (openSheetId) goBack(); }
function closeSheetNow() {
  if (!openSheetId) return;
  $(openSheetId).hidden = true; $('scrim').hidden = true;
  if (openSheetId === 'queueSheet') revokeThumbs();
  openSheetId = null;
  if (state.screen === 'cam') { updateCtx(); drawPreview(); updateOrientation(); }
}

/* ======================= login / session ======================= */
async function doLogin(e) {
  e.preventDefault();
  $('loginErr').textContent = '';
  if (IS_NATIVE) {
    let u = $('loginNas').value.trim();
    if (!u) { $('loginErr').textContent = 'Enter the NAS address (ask your admin)'; return; }
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    nasUrl = u; await kvSet('nasUrl', u);
  }
  $('loginBtn').disabled = true;
  const r = await api('login.php', { json: { username: $('loginUser').value.trim(), pin: $('loginPin').value } });
  $('loginBtn').disabled = false;
  if (!r.ok) { $('loginErr').textContent = r.error || 'Login failed'; return; }
  state.auth = { token: r.token, user: r.user, name: r.name, role: r.role, shared: !!r.shared };
  await kvSet('auth', state.auth);
  $('loginPin').value = '';
  navigator.storage?.persist?.().catch(() => {});
  if (state.auth.shared && !state.photographer) return askPhotographer();
  enterApp();
}
/* Shared staff login: each phone says once who is taking the photos */
function askPhotographer() {
  show('login');
  $('loginForm').hidden = true; $('nameForm').hidden = false;
  $('photographerName').value = state.photographer || '';
  setTimeout(() => $('photographerName').focus(), 50);
}
async function savePhotographer(e) {
  e.preventDefault();
  const n = $('photographerName').value.trim();
  if (!n) return;
  state.photographer = n; await kvSet('photographer', n);
  $('nameForm').hidden = true; $('loginForm').hidden = false;
  enterApp();
}
function sessionExpired() {
  if (!state.auth) return;
  toast('Login expired — please log in again. Waiting photos are kept.', true, 5000);
  kvDel('auth'); state.auth = null;
  if (state.rec) stopRecording();
  stopCamera(); closeSheetNow(); showLogin();
}
let loginLogoUrl;
/** Login screen shows the company logo once this phone has it (after the first login); else the app icon. */
async function showLoginLogo() {
  let l = null;
  try { l = await kvGet('logo'); } catch {}
  const img = $('loginLogo');
  if (l?.data) {
    if (loginLogoUrl) URL.revokeObjectURL(loginLogoUrl);
    loginLogoUrl = URL.createObjectURL(new Blob([l.data], { type: 'image/png' }));
    img.src = loginLogoUrl; img.alt = 'Company logo'; img.classList.add('company');
  } else {
    img.src = 'icons/icon-192.png'; img.alt = ''; img.classList.remove('company');
  }
}
function showLogin() {
  showLoginLogo();
  $('nasRow').hidden = !IS_NATIVE;
  $('apkRow').hidden = !(/Android/i.test(navigator.userAgent) && !IS_NATIVE && !ANDROID_APP);
  $('loginNas').value = nasUrl;
  $('loginForm').hidden = false; $('nameForm').hidden = true;
  show('login');
}
async function logout() {
  const n = (await qAll()).length;
  if (n && !confirm(`${n} photo(s)/video(s) are not uploaded yet and will be lost if you log out. Log out anyway?`)) return;
  for (const r of await qAll()) await qRemove(r.uid);
  await kvDel('auth');
  state.auth = null;
  stopCamera(); stopGps(); closeSheetNow();
  showLogin();
}
function enterApp() {
  show('jobs');
  renderJobs();
  startGps();
  refreshBadge();
  loadBootstrap();
  syncQueue();
}
async function loadBootstrap() {
  const r = await api('bootstrap.php', { timeout: 15000 });
  if (!r.ok) {
    $('jobsNote').textContent = r.status === 0 ? 'Offline — showing the last saved job list.' : (r.error || '');
    return r;
  }
  state.jobs = r.jobs; state.settings = r.settings;
  state.auth.role = r.role; state.auth.name = r.name; state.auth.shared = !!r.shared;
  state.server = { storage_exists: r.storage_exists, storage_writable: r.storage_writable, secret_is_default: r.secret_is_default, limits: r.limits, submitted_keep_days: r.submitted_keep_days };
  kvSet('auth', state.auth); kvSet('jobs', r.jobs); kvSet('settings', r.settings);
  $('jobsNote').textContent = '';
  // The current job may have been renamed or removed by an admin
  if (state.job) state.job = r.jobs.find((j) => j.id === state.job.id) || state.job;
  renderJobs();
  loadLogo();
  if (state.screen === 'cam') { updateCtx(); drawPreview(); }
  return r;
}

/* ======================= company logo (kept for offline use) ======================= */
async function loadLogo() {
  const v = state.settings?.logo_version || 0;
  let cached = await kvGet('logo');
  if (!v) { state.logo = null; state.logoVersion = 0; if (cached) kvDel('logo'); return; }
  if (!cached || cached.version !== v) {
    const r = await api('logo.php', { raw: true, timeout: 20000 });
    if (r && r.ok) { cached = { version: v, data: await r.arrayBuffer() }; await kvSet('logo', cached); }
  }
  if (cached && state.logoVersion !== cached.version) {
    try {
      state.logo = await toBitmap(new Blob([cached.data], { type: 'image/png' }));
      state.logoVersion = cached.version;
      drawPreview();
    } catch (e) { console.warn('logo', e); }
  }
}

/* ======================= theme (System default / Dark / Light, per phone) ======================= */
const darkMq = window.matchMedia?.('(prefers-color-scheme: dark)');
function currentTheme() { return document.documentElement.dataset.theme || 'system'; }
function applyTheme(t) {
  if (!['system', 'dark', 'light'].includes(t)) t = 'system';
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('fc-theme', t); } catch {}
  const dark = t === 'dark' || (t === 'system' && (darkMq ? darkMq.matches : true));
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#0e1113' : '#f3f5f7');
  document.querySelectorAll('#themeSeg [data-theme]').forEach((b) => b.setAttribute('aria-checked', b.dataset.theme === t));
  try { ANDROID_APP?.setDarkTheme?.(dark); } catch {}         // status/navigation bar colours in the Android app
}
darkMq?.addEventListener?.('change', () => { if (currentTheme() === 'system') applyTheme('system'); });

/* ======================= drop-down lists ======================= */
/* Every <select> gets a button + a list drawn by the app, so drop-downs look the same on every phone
   (Android otherwise shows a full-screen radio-button dialog). The real <select> stays in the page,
   hidden, and keeps the value, so the rest of the code uses it as before. */
const SEL_VALUE = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
const SEL_INDEX = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex');
let ddOpen = null;
function enhanceSelect(sel) {
  if (sel.dataset.dd) return;
  sel.dataset.dd = '1';
  const btn = document.createElement('button');
  btn.type = 'button'; btn.className = 'dd-btn'; btn.setAttribute('aria-haspopup', 'listbox'); btn.setAttribute('aria-expanded', 'false');
  if (sel.getAttribute('aria-label')) btn.setAttribute('aria-label', sel.getAttribute('aria-label'));
  sel.classList.add('dd-native'); sel.tabIndex = -1; sel.setAttribute('aria-hidden', 'true');
  sel.after(btn);
  const sync = () => { const o = sel.options[SEL_INDEX.get.call(sel)]; btn.textContent = o ? o.text : ''; btn.disabled = sel.disabled; };
  // Keep the button text right when code sets .value / .selectedIndex or rebuilds the options
  Object.defineProperty(sel, 'value', { configurable: true, get() { return SEL_VALUE.get.call(this); }, set(v) { SEL_VALUE.set.call(this, v); sync(); } });
  Object.defineProperty(sel, 'selectedIndex', { configurable: true, get() { return SEL_INDEX.get.call(this); }, set(v) { SEL_INDEX.set.call(this, v); sync(); } });
  new MutationObserver(sync).observe(sel, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled', 'selected'] });
  sel.addEventListener('change', sync);
  btn.addEventListener('click', (e) => { e.preventDefault(); openDropdown(sel, btn); });
  sync();
}
function closeDropdown() {
  if (!ddOpen) return;
  const { list, btn } = ddOpen;
  ddOpen = null;
  list.remove(); btn.setAttribute('aria-expanded', 'false');
  document.removeEventListener('pointerdown', ddOutside, true);
  document.removeEventListener('keydown', ddKey, true);
  window.removeEventListener('resize', closeDropdown);
  document.removeEventListener('scroll', ddScroll, true);
}
function ddOutside(e) { if (ddOpen && !ddOpen.list.contains(e.target) && !ddOpen.btn.contains(e.target)) closeDropdown(); }
// Close on page scroll — but not for a scroll that was still settling when the list opened
function ddScroll(e) { if (ddOpen && !ddOpen.list.contains(e.target) && Date.now() - ddOpen.at > 250) closeDropdown(); }
function ddKey(e) {
  if (!ddOpen) return;
  const items = [...ddOpen.list.querySelectorAll('li:not(.off)')];
  let i = items.indexOf(ddOpen.list.querySelector('li.hi'));
  if (e.key === 'Escape') { e.preventDefault(); const b = ddOpen.btn; closeDropdown(); b.focus(); }
  else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    i = Math.max(0, Math.min(items.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)));
    items.forEach((li, k) => li.classList.toggle('hi', k === i)); items[i]?.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); items[i]?.click(); }
}
function openDropdown(sel, btn) {
  const same = ddOpen && ddOpen.sel === sel;
  closeDropdown();
  if (same || sel.disabled) return;
  const list = document.createElement('ul');
  list.className = 'dd-list'; list.setAttribute('role', 'listbox');
  const cur = SEL_INDEX.get.call(sel);
  [...sel.options].forEach((o, i) => {
    if (o.hidden) return;
    const li = document.createElement('li');
    li.setAttribute('role', 'option'); li.textContent = o.text; li.dataset.i = i;
    if (i === cur) { li.classList.add('on', 'hi'); li.setAttribute('aria-selected', 'true'); }
    if (o.disabled) li.classList.add('off');
    list.appendChild(li);
  });
  list.addEventListener('click', (e) => {
    const li = e.target.closest('li'); if (!li || li.classList.contains('off')) return;
    const i = +li.dataset.i;
    closeDropdown();
    if (i !== SEL_INDEX.get.call(sel)) {
      sel.selectedIndex = i;
      sel.dispatchEvent(new Event('input', { bubbles: true }));
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    }
    btn.focus();
  });
  document.body.appendChild(list);
  // Open below the field, or above it when there is more room there (like a desktop browser)
  const r = btn.getBoundingClientRect(), m = 8, vw = window.innerWidth, vh = window.innerHeight;
  list.style.minWidth = r.width + 'px';
  list.style.maxWidth = (vw - 2 * m) + 'px';
  const w = list.offsetWidth, full = list.scrollHeight;
  const below = vh - r.bottom - m, above = r.top - m;
  const down = below >= Math.min(full, 260) || below >= above;
  const h = Math.min(full, down ? below : above);
  list.style.maxHeight = h + 'px';
  list.style.left = Math.max(m, Math.min(r.left, vw - m - w)) + 'px';
  list.style.top = (down ? r.bottom + 2 : r.top - 2 - h) + 'px';
  list.querySelector('li.on')?.scrollIntoView({ block: 'nearest' });
  btn.setAttribute('aria-expanded', 'true');
  ddOpen = { sel, btn, list, at: Date.now() };
  document.addEventListener('pointerdown', ddOutside, true);
  document.addEventListener('keydown', ddKey, true);
  window.addEventListener('resize', closeDropdown);
  document.addEventListener('scroll', ddScroll, true);
}
function enhanceAllSelects() { document.querySelectorAll('select:not([data-dd])').forEach(enhanceSelect); }

/* ======================= confirmation dialog ======================= */
function askConfirm({ title, html, yes }) {
  return new Promise((resolve) => {
    $('confirmTitle').textContent = title;
    $('confirmBody').innerHTML = html;
    $('confirmYes').textContent = yes;
    $('confirmDlg').hidden = false;
    $('confirmNo').focus();
    const done = (v) => {
      $('confirmDlg').hidden = true;
      $('confirmYes').onclick = $('confirmNo').onclick = $('confirmDlg').onclick = null;
      resolve(v);
    };
    $('confirmYes').onclick = () => done(true);
    $('confirmNo').onclick = () => done(false);
    $('confirmDlg').onclick = (e) => { if (e.target === $('confirmDlg')) done(false); };
  });
}

/* ======================= jobs ======================= */
const isSubmitted = (j) => j.status === 'submitted';
const KEEP_DAYS = () => state.server?.submitted_keep_days || 30;
function fmtDay(iso) { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }); }
function renderJobs() {
  const admin = state.auth?.role === 'admin';
  // Admins have two separate lists: open "Jobs" and "Completed Jobs" (submitted). Staff only see open jobs.
  const tab = admin && state.jobTab === 'done' ? 'done' : 'open';
  const doneAll = admin ? state.jobs.filter(isSubmitted) : [];
  $('jobsWho').textContent = state.auth ? `${state.auth.name}${admin ? ' · Admin' : ''}` : '';
  $('jobsTitle').textContent = tab === 'done' ? 'Completed Jobs' : 'Jobs';
  $('jobTabs').hidden = !admin || !GAS_URL;
  $('jobTabs').querySelectorAll('[data-tab]').forEach((b) => {
    b.setAttribute('aria-checked', b.dataset.tab === tab);
    if (b.dataset.tab === 'done') b.textContent = `Completed Jobs${doneAll.length ? ` (${doneAll.length})` : ''}`;
  });
  $('newJobBtn').hidden = !admin || tab === 'done';
  const q = $('jobSearch').value.trim().toLowerCase();
  const match = (j) => !q || j.job_number.toLowerCase().includes(q) || j.site_name.toLowerCase().includes(q);
  const loc = (j) => `${esc(j.site_name)}${j.location_name ? ' · ' + esc(j.location_name) : ''}`;

  if (tab === 'done') {
    const done = doneAll.filter(match).sort((a, b) => String(b.submitted_at).localeCompare(String(a.submitted_at)));
    $('jobList').innerHTML = done.length ? done.map((j) => {
      const left = Math.max(0, KEEP_DAYS() - Math.floor((Date.now() - new Date(j.submitted_at)) / 86400000));
      return `
      <li class="job done" data-id="${esc(j.id)}">
        <div class="job-open"><span class="job-no">${esc(j.job_number)}</span><span class="job-site">${loc(j)}</span>
          <span class="job-tag done">Submitted ${esc(fmtDay(j.submitted_at))}${j.submitted_by ? ' by ' + esc(j.submitted_by) : ''} · leaves this list in ${left} day${left === 1 ? '' : 's'}</span></div>
        <button class="job-edit job-reopen">Reopen</button>
      </li>`;
    }).join('') : `<li class="empty">${doneAll.length ? 'No completed job matches your search.' : `No completed jobs. Submitted jobs are listed here for ${KEEP_DAYS()} days.`}</li>`;
    return;
  }
  const open = state.jobs.filter((j) => !isSubmitted(j) && match(j));
  const anyOpen = state.jobs.some((j) => !isSubmitted(j));
  $('jobList').innerHTML = open.length ? open.map((j) => `
    <li class="job ${j.active ? '' : 'inactive'}" data-id="${esc(j.id)}">
      <button class="job-open"><span class="job-no">${esc(j.job_number)}</span><span class="job-site">${loc(j)}</span>
        ${j.active ? '' : '<span class="job-tag">Hidden from staff</span>'}</button>
      ${admin ? '<button class="job-edit">Edit</button>' : ''}
    </li>`).join('')
    : `<li class="empty">${anyOpen ? 'No job matches your search.' : admin ? 'No open jobs. Tap “+ New job” to create one.' : 'No jobs yet. Ask an admin to create one.'}</li>`;
}
async function onJobListClick(e) {
  const li = e.target.closest('.job'); if (!li) return;
  const job = state.jobs.find((j) => j.id === li.dataset.id); if (!job) return;
  if (e.target.closest('.job-reopen')) return reopenJob(job);
  if (isSubmitted(job)) return;
  if (e.target.closest('.job-edit')) { state.editingJob = job; openSheet('jobSheet'); return; }
  state.job = job;
  $('tpJobNo').textContent = job.job_number;
  $('tpSite').textContent = job.site_name;
  $('submitBox').hidden = !GAS_URL;
  if (job.save_local) { try { ANDROID_APP?.askStoragePermission?.(); } catch {} }   // older Android versions need it
  pushNav(); show('typePick');
}
async function submitJob() {
  const job = state.job; if (!job) return;
  if (!navigator.onLine) { toast('Connect to the internet to submit the job', true); return; }
  const waiting = (await qAll()).filter((r) => r.meta?.job_id === job.id).length;
  const ok = await askConfirm({
    title: `Submit job ${job.job_number}?`,
    html: `<p>Only submit when <b>all tests for this job are finished</b>.</p>
      <p>After submitting, the job <b>disappears from the job list</b> and no more photos or videos can be taken for it.
      Admins can still see it under “Completed jobs”.</p>
      <p>Photos and videos already taken stay in ${esc(STORE_THE)}.</p>
      ${waiting ? `<p class="warn-line">${waiting} photo(s)/video(s) of this job are still waiting on this phone — they will still upload. Keep the app open until they are done.</p>` : ''}`,
    yes: 'Yes, submit job',
  });
  if (!ok) return;
  $('submitJobBtn').disabled = true;
  try {
    const r = await api('job.php', { json: { action: 'submit', id: job.id, photographer_name: state.photographer || '' } });
    if (!r.ok) { toast(r.error || 'Could not submit the job', true); return; }
    toast(`Job ${job.job_number} submitted`);
    const i = state.jobs.findIndex((j) => j.id === job.id);
    if (i >= 0) state.jobs[i] = r.job;
    if (state.auth?.role !== 'admin') state.jobs = state.jobs.filter((j) => j.id !== job.id);
    kvSet('jobs', state.jobs);
    state.job = null;
    renderJobs();
    goBack();
    loadBootstrap();
  } finally { $('submitJobBtn').disabled = false; }
}
async function reopenJob(job) {
  const ok = await askConfirm({
    title: `Reopen job ${job.job_number}?`,
    html: '<p>The job goes back into the job list, so staff can take photos for it again.</p>',
    yes: 'Reopen job',
  });
  if (!ok) return;
  const r = await api('job.php', { json: { action: 'reopen', id: job.id } });
  if (!r.ok) { toast(r.error || 'Could not reopen the job', true); return; }
  toast(`Job ${job.job_number} reopened`);
  loadBootstrap();
}
function renderJobSheet() {
  const j = state.editingJob;
  $('jobSheetTitle').textContent = j ? 'Edit job' : 'New job';
  $('jobSave').textContent = j ? 'Save changes' : 'Create job';
  $('jNo').value = j?.job_number || '';
  $('jSite').value = j?.site_name || '';
  $('jLoc').value = j?.location_name || '';
  $('jActiveRow').hidden = !j;
  $('jActive').checked = j ? !!j.active : true;
  $('jSaveLocal').checked = !!j?.save_local;   // off by default
  $('jobDelete').hidden = !j || !GAS_URL;      // admins can delete a wrong job entry
  $('jobErr').textContent = '';
  updateFolderHint();
}
function updateFolderHint() {
  const no = $('jNo').value.trim(), site = $('jSite').value.trim();
  const loc = $('jLoc').value.trim();
  $('jFolder').textContent = no && site ? `${STORE} folder: Testing Photographs / ${no} - ${site}${loc ? ' - ' + loc : ''}` : '';
}
async function saveJob(e) {
  e.preventDefault();
  const j = state.editingJob;
  $('jobSave').disabled = true; $('jobErr').textContent = '';
  try {
    const r = await api('admin.php', { json: { action: 'job_save', id: j?.id || '', job_number: $('jNo').value, site_name: $('jSite').value, location_name: $('jLoc').value, save_local: $('jSaveLocal').checked } });
    if (!r.ok) { $('jobErr').textContent = r.error; return; }
    if (j && j.active !== $('jActive').checked) {
      const r2 = await api('admin.php', { json: { action: 'job_active', id: j.id, active: $('jActive').checked } });
      if (!r2.ok) { $('jobErr').textContent = r2.error; return; }
    }
    toast(j ? 'Job updated' : 'Job created');
    state.editingJob = null;
    closeSheet();
    loadBootstrap();
  } finally { $('jobSave').disabled = false; }
}

/** Admin: delete a wrong job entry. Photos already in Google Drive are never deleted. */
async function deleteJob() {
  const j = state.editingJob; if (!j) return;
  const waiting = (await qAll()).filter((r) => r.meta?.job_id === j.id).length;
  const ok = await askConfirm({
    title: `Delete job ${j.job_number}?`,
    html: `<p>The job is removed from the job list for everyone. Use this for a <b>wrong job entry</b>.</p>
      <p><b>Photos and videos already in ${esc(STORE_THE)} are not deleted.</b> If the job has no photos, its (empty) folder is removed.</p>
      ${waiting ? `<p class="warn-line">${waiting} photo(s)/video(s) of this job are still waiting on this phone — they will still upload.</p>` : ''}`,
    yes: 'Delete job',
  });
  if (!ok) return;
  $('jobDelete').disabled = true;
  try {
    const r = await api('admin.php', { json: { action: 'job_delete', id: j.id } });
    if (!r.ok) { $('jobErr').textContent = r.error || 'Could not delete the job'; return; }
    state.jobs = state.jobs.filter((x) => x.id !== j.id); kvSet('jobs', state.jobs);
    state.editingJob = null;
    toast(r.folder_kept ? `Job ${j.job_number} deleted — its photos stay in ${STORE_THE}` : `Job ${j.job_number} deleted`);
    closeSheet(); renderJobs(); loadBootstrap();
  } finally { $('jobDelete').disabled = false; }
}

/* ======================= Lab / Field choice ======================= */
function pickType(type) {
  askMotionPermission();                       // iPhone: needed to notice the phone is held sideways
  state.type = type;
  pushNav();
  enterCamera();
  const d = currentDetails();
  if (detailsMissing()) openSheet('detailsSheet');
}

/* ======================= details for the current photo ======================= */
function detailsMissing() {
  if (state.type === 'Laboratory' && stampConf('Laboratory').test_name && !currentDetails().test_name) return 'Test name';
  if (state.type === 'Field' && stampConf('Field').test_name && !currentDetails().field_test) return 'Field test name';
  return '';
}
function updateCtx() {
  if (!state.job) return;
  $('ctxType').textContent = state.type === 'Laboratory' ? 'Laboratory' : 'Field';
  $('ctxJob').textContent = `${state.job.job_number} · ${state.job.site_name}`;
  const d = currentDetails(), lab = state.type === 'Laboratory';
  $('ctxSub').textContent = lab ? '' : locationName();
  // The clearly visible "✎ … Change" button under the top bar shows the test (and field text)
  const test = lab ? d.test_name : d.field_test;
  $('editTest').textContent = test ? 'Test: ' + test : (lab ? 'Choose the test' : 'Choose the field test');
  $('editText').hidden = lab;
  $('editText').textContent = d.custom_text ? 'Text: ' + d.custom_text : 'Add your text on the photo';
  $('editBtn').classList.toggle('missing', !!detailsMissing());
  $('stampBtn').hidden = state.auth?.role !== 'admin';
}
function renderDetails() {
  const lab = state.type === 'Laboratory', d = currentDetails();
  $('detailsTitle').textContent = lab ? 'Laboratory details' : 'Field details';
  document.querySelectorAll('#detailsForm [data-for]').forEach((el) => el.classList.toggle('show', el.dataset.for === state.type));
  const cur = lab ? d.test_name : d.field_test;
  $('testLabel').textContent = lab ? 'Test name' : 'Field test name';
  $('testReq').hidden = !stampConf(state.type).test_name;
  const names = (lab ? state.settings?.test_names : state.settings?.field_test_names) || [];
  const other = !!cur && !names.includes(cur);
  $('fTestSel').innerHTML = `<option value="">— Select ${lab ? 'test' : 'field test'} —</option>`
    + names.map((n) => `<option value="${esc(n)}" ${n === cur ? 'selected' : ''}>${esc(n)}</option>`).join('')
    + `<option value="__other" ${other ? 'selected' : ''}>Other (type it)</option>`;
  $('fTest').value = other ? cur : '';
  $('fTestOtherRow').hidden = !other;
  $('fText').value = d.custom_text;
  $('detailsErr').textContent = '';
}
function chosenTest() {
  const v = $('fTestSel').value;
  return v === '__other' ? $('fTest').value.trim() : v;
}
function saveDetails(e) {
  e.preventDefault();
  const d = currentDetails();
  if (state.type === 'Laboratory') {
    d.test_name = chosenTest();
    if (stampConf('Laboratory').test_name && !d.test_name) { $('detailsErr').textContent = 'Please choose or type the test name'; return; }
  } else {
    d.field_test = chosenTest();
    if (stampConf('Field').test_name && !d.field_test) { $('detailsErr').textContent = 'Please choose or type the field test name'; return; }
    d.custom_text = $('fText').value.trim();
  }
  kvSet('jobDetails', state.jobDetails);
  closeSheet();
}

/* ======================= stamp on/off ======================= */
function toggleRows(items, conf, prefix) {
  return items.map(([k, label]) => `<label class="toggle-row">${esc(label)}<input type="checkbox" data-k="${prefix}${k}" ${conf[k] ? 'checked' : ''}></label>`).join('');
}
function selectRow(label, key, opts, val) {
  return `<label class="toggle-row">${esc(label)}<select data-k="${key}">${opts.map(([v, t]) => `<option value="${v}" ${v === val ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></label>`;
}
/* ======================= GPS & location name ======================= */
function startGps() {
  if (!('geolocation' in navigator) || state.gpsWatch !== null) return;
  state.gpsWatch = navigator.geolocation.watchPosition((p) => {
    state.gps = { lat: p.coords.latitude, lon: p.coords.longitude, accuracy: p.coords.accuracy, altitude: p.coords.altitude, at: Date.now() };
    renderGps();
  }, (err) => { renderGps(err.code === 1 ? 'GPS blocked' : 'No GPS'); },
  { enableHighAccuracy: true, maximumAge: 10000, timeout: 30000 });
}
function stopGps() { if (state.gpsWatch !== null) navigator.geolocation.clearWatch(state.gpsWatch); state.gpsWatch = null; }
function freshGps() { return state.gps && Date.now() - state.gps.at < 120000 ? state.gps : null; }
function renderGps(msg) {
  const p = $('gpsPill'), g = freshGps();
  if (!g) { p.textContent = msg || 'No GPS'; p.className = 'pill bad'; return; }
  // Accuracy is shown here only — never stamped on the photo (it is kept in the CSV log)
  const acc = Math.round(g.accuracy);
  p.textContent = `±${acc} m · ${acc <= 10 ? 'Good' : acc <= 25 ? 'Fair' : 'Weak'}`;
  p.className = 'pill gps ' + (acc <= 10 ? 'ok' : acc <= 25 ? 'warn' : 'bad');
}
/** Tap the GPS pill: the current coordinates with their accuracy (for information only). */
function showGpsInfo() {
  const g = freshGps();
  if (!g) { toast('No GPS position yet — go outside / wait a moment', true); return; }
  const fmt = stampConf('Field').coord_format || 'utm';
  toast(`${fmtCoords(g.lat, g.lon, fmt)}  ·  accuracy ±${Math.round(g.accuracy)} m (not printed on the photo)`, false, 5000);
}
/* ======================= orientation (photos landscape only) ======================= */
let heldSideways = null;          // from the motion sensor; null = unknown
/* Which way the phone is turned: +1 = turned left (top of the phone points left), -1 = turned right,
   0 = upright. Lying flat (pointing down at the ground) keeps the last value. iPhones report the
   sensor with the opposite sign, so it is flipped there. */
let sideDir = 0;
const IOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
window.addEventListener('devicemotion', (e) => {
  const g = e.accelerationIncludingGravity;
  if (!g || g.x == null || g.y == null) return;
  const ax = Math.abs(g.x), ay = Math.abs(g.y);
  const prev = sideDir;
  if (ax > 6 && ax > ay + 2) { heldSideways = true; sideDir = (IOS ? -g.x : g.x) > 0 ? 1 : -1; }
  else if (ay > 6 && ay > ax + 2) { heldSideways = false; sideDir = 0; }
  if (prev !== sideDir && state.screen === 'cam') { updateOrientation(); drawPreview(); }
});
/** iPhone asks once for "Motion & Orientation" — must be called from a tap. */
function askMotionPermission() {
  try { if (typeof DeviceMotionEvent?.requestPermission === 'function') DeviceMotionEvent.requestPermission().catch(() => {}); } catch {}
}
function frameIsLandscape() { const v = $('video'); return v.videoWidth > v.videoHeight; }
/** Camera-app style: phone held sideways while the screen stays upright → the photo is turned to landscape. */
function sideCapture() { return state.mode === 'photo' && !!$('video').videoWidth && !frameIsLandscape() && sideDir !== 0; }
/** Only FIELD photos must be landscape; Laboratory photos and all videos can be either way. */
function photoBlocked() { return state.type === 'Field' && state.mode === 'photo' && !!$('video').videoWidth && !frameIsLandscape() && !sideCapture(); }
/** Turn an upright (portrait) camera picture into the landscape photo the user is holding:
 *  dir +1 (turned left) → rotate 90° anticlockwise; dir -1 (turned right) → 90° clockwise. */
function rotateSideways(img, dir) {
  const w = img.width, h = img.height, c = document.createElement('canvas');
  c.width = h; c.height = w;
  const ctx = c.getContext('2d');
  if (dir > 0) { ctx.translate(0, w); ctx.rotate(-Math.PI / 2); } else { ctx.translate(h, 0); ctx.rotate(Math.PI / 2); }
  ctx.drawImage(img, 0, 0);
  return c;
}
function updateOrientation() {
  if (state.screen !== 'cam') return;
  const blocked = photoBlocked(), side = sideCapture();
  $('sideBadge').hidden = !side || !!openSheetId || !$('review').hidden;
  const cam = $('cam');
  cam.classList.toggle('side-left', side && sideDir > 0);    // turn the small buttons so they read the right way up
  cam.classList.toggle('side-right', side && sideDir < 0);
  $('rotateHint').hidden = !blocked || !!openSheetId || !$('review').hidden || !$('camError').hidden;
  $('shutter').classList.toggle('blocked', blocked);
  $('shutter').setAttribute('aria-disabled', blocked);
  if (blocked) {
    const appRotates = typeof ANDROID_APP?.setCameraMode === 'function';   // Android app turns the screen itself
    $('rotateMsg').textContent = heldSideways && !appRotates
      ? 'Your phone is sideways but the screen did not turn. Switch on Auto-rotate (swipe down from the top of the screen), then try again.'
      : 'Field photos can only be taken in landscape. Videos can be taken either way.';
  }
}

/* ======================= camera ======================= */
async function enterCamera() {
  show('cam');
  setMode(state.mode, true);
  updateCtx(); renderGps(); renderNet();
  await startCamera();
}
function leaveCamera() { stopCamera(); }
async function startCamera() {
  stopCamera();
  $('camError').hidden = true;
  if (!navigator.mediaDevices?.getUserMedia) return camFail('This browser cannot open the camera. Open the app over https:// in Chrome (Android) or Safari (iPhone).');
  // Phones with several back lenses: use the MAIN camera (not telephoto/macro), so 1.0× looks the same on every phone
  const mainId = state.facing === 'environment' && !state.noMainCam ? mainBackCameraId() : null;
  const which = mainId ? { deviceId: { exact: mainId } } : { facingMode: { ideal: state.facing } };
  const video = state.mode === 'video'
    ? (() => {                                   // "Device best" asks for the highest the phone offers (up to 4K)
        const r = state.settings?.video?.max_res || 3840;
        return { ...which, width: { ideal: r }, height: { ideal: Math.round(r * 9 / 16) }, frameRate: { ideal: 30 } };
      })()
    // Photos are taken with the camera's still-photo capture where available, so the live picture can be
    // lighter (faster, smoother); without it (iPhone) the photo comes from the live picture, so ask for the most.
    : ('ImageCapture' in window
      ? { ...which, width: { ideal: 1920 }, height: { ideal: 1440 } }
      : { ...which, width: { ideal: 4032 }, height: { ideal: 3024 } });
  const wantAudio = state.mode === 'video' && state.settings?.video?.audio !== false;
  try {
    state.stream = await openCamera(video, wantAudio);
  } catch (e) {
    if (mainId && (e.name === 'OverconstrainedError' || e.name === 'NotFoundError')) {   // remembered lens is gone
      forgetMainCamera(); state.noMainCam = true; return startCamera();   // don't try again this session
    }
    if (wantAudio && e.name === 'NotAllowedError') {
      try { state.stream = await openCamera(video, false); toast('Microphone not allowed — videos will be silent'); }
      catch (e2) { return camFail(camMsg(e2)); }
    } else return camFail(camMsg(e));
  }
  // First time on this phone: once the camera is allowed, the lens names are known — switch to the main lens if needed
  if (state.facing === 'environment' && !mainId && !state.noMainCam && await findMainBackCamera()) {
    const now = state.stream.getVideoTracks()[0]?.getSettings?.().deviceId;
    if (now && now !== mainBackCameraId()) return startCamera();
  }
  state.streamMode = state.mode;
  const v = $('video');
  v.srcObject = state.stream;
  try { await v.play(); } catch {}
  state.track = state.stream.getVideoTracks()[0];
  state.imageCapture = null;
  if (state.mode === 'photo' && 'ImageCapture' in window) { try { state.imageCapture = new ImageCapture(state.track); } catch {} }
  const caps = state.track.getCapabilities?.() || {};
  // Pinch-to-zoom: the camera's own zoom when the phone offers it, otherwise digital zoom
  state.zoomHw = caps.zoom && caps.zoom.max > caps.zoom.min ? caps.zoom : null;
  state.zoom = 1; applyZoom(1, true);
  $('torchBtn').hidden = !caps.torch;
  state.torch = false; $('torchBtn').classList.remove('on');
  layoutPreview();
}
function camMsg(e) {
  return e.name === 'NotAllowedError'
    ? 'Camera permission was denied. Allow camera access for this app in your phone/browser settings, then try again.'
    : 'Could not open the camera (' + e.name + ').';
}
function stopCamera() {
  state.stream?.getTracks().forEach((t) => t.stop());
  state.stream = state.track = state.imageCapture = null;
}
/* ---------- main back camera (Android phones with several back lenses) ---------- */
function mainBackCameraId() { try { return localStorage.getItem('fc-main-cam') || null; } catch { return null; } }
function forgetMainCamera() { try { localStorage.removeItem('fc-main-cam'); } catch {} }
/** Android names the lenses "camera2 0, facing back", "camera2 2, facing back"…; the lowest number is the main camera.
 *  iPhones pick the main camera by themselves, so they are left alone. Returns true when found. */
async function findMainBackCamera() {
  if (IOS || !navigator.mediaDevices?.enumerateDevices) return false;
  try {
    const cams = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === 'videoinput' && /back|rear|environment/i.test(d.label));
    if (cams.length < 2) return false;                     // only one back camera: nothing to choose
    const num = (d) => { const m = /camera\s*2?\s*(\d+)/i.exec(d.label); return m ? +m[1] : 999; };
    const skip = (d) => /tele|macro|depth|ultra|wide-angle|wide angle/i.test(d.label) ? 1 : 0;
    cams.sort((a, b) => skip(a) - skip(b) || num(a) - num(b));
    if (!cams[0].deviceId) return false;
    localStorage.setItem('fc-main-cam', cams[0].deviceId);
    return true;
  } catch { return false; }
}

/** Opens the camera, asking for its zoom control too (Chrome); falls back when that isn't supported. */
async function openCamera(video, audio) {
  try { return await navigator.mediaDevices.getUserMedia({ video: { ...video, zoom: true }, audio }); }
  catch (e) {
    if (e.name === 'NotAllowedError') throw e;
    return navigator.mediaDevices.getUserMedia({ video, audio });
  }
}

/* ======================= aspect ratio (admin setting for photos and for videos) ======================= */
const ASPECTS = { '4:3': 4 / 3, '3:2': 3 / 2, '16:9': 16 / 9 };
/** Long side ÷ short side chosen by the admin, or 0 = keep the camera's own shape. */
function aspectValue(mode) { return ASPECTS[state.settings?.[mode === 'video' ? 'video' : 'photo']?.aspect] || 0; }
/** Largest centred area of w×h with that shape (keeps portrait/landscape as it is). */
function aspectRect(w, h, r) {
  if (!r) return { x: 0, y: 0, w, h };
  const land = w >= h;
  let L = land ? w : h, S = land ? h : w;
  if (L / S > r) L = S * r; else S = L / r;
  const cw = land ? L : S, ch = land ? S : L;
  return { x: (w - cw) / 2, y: (h - ch) / 2, w: cw, h: ch };
}
/** Photo: cut the centre to the chosen shape. */
function aspectCrop(img, r) {
  if (!r) return img;
  const a = aspectRect(img.width, img.height, r);
  const cw = Math.round(a.w), ch = Math.round(a.h);
  if (cw >= img.width && ch >= img.height) return img;
  const c = document.createElement('canvas'); c.width = cw; c.height = ch;
  c.getContext('2d').drawImage(img, a.x, a.y, a.w, a.h, 0, 0, cw, ch);
  img.close?.();
  return c;
}

/* ======================= pinch to zoom the camera (not the screen) ======================= */
const MAX_DIGITAL_ZOOM = 5;
function maxZoom() { return state.zoomHw ? Math.min(state.zoomHw.max, 10) : MAX_DIGITAL_ZOOM; }
/** Digital zoom factor (1 when the camera zooms itself). */
function digitalZoom() { return state.zoomHw ? 1 : Math.max(1, state.zoom || 1); }
/* Smooth zoom, like a camera app: the pinch sets a target and the zoom glides towards it on every
   screen frame (eases in and out). The camera's own zoom gets the newest value as soon as it has
   finished applying the previous one, so it never lags behind or piles up. */
const zoomAnim = { target: 1, raf: 0, hwBusy: false, hwNext: null };
let zoomPillT;
function clampZoom(z) {
  const minZ = state.zoomHw ? Math.max(1, state.zoomHw.min) : 1;
  return Math.max(minZ, Math.min(maxZoom(), z));
}
function applyZoom(z, instant) {
  zoomAnim.target = clampZoom(z);
  const pill = $('zoomPill');
  pill.textContent = zoomAnim.target.toFixed(1) + '×';
  clearTimeout(zoomPillT);
  if (instant) {                                         // new camera: jump straight there
    cancelAnimationFrame(zoomAnim.raf); zoomAnim.raf = 0;
    renderZoom(zoomAnim.target);
    pill.hidden = zoomAnim.target <= 1;
    return;
  }
  pill.hidden = false;
  if (zoomAnim.target <= 1) zoomPillT = setTimeout(() => { pill.hidden = true; }, 1200);
  if (!zoomAnim.raf) zoomAnim.raf = requestAnimationFrame(zoomStep);
}
function zoomStep() {
  zoomAnim.raf = 0;
  const cur = state.zoom || 1, d = zoomAnim.target - cur;
  // move 30 % of the remaining distance each frame (~60 per second) → quick but smooth
  const next = Math.abs(d) < 0.004 ? zoomAnim.target : cur + d * 0.3;
  renderZoom(next);
  if (next !== zoomAnim.target) zoomAnim.raf = requestAnimationFrame(zoomStep);
}
function renderZoom(z) {
  state.zoom = z;
  if (state.zoomHw) { $('video').style.transform = ''; sendHwZoom(z); }
  else $('video').style.transform = z > 1 ? `scale(${z})` : '';
  clipZoomedVideo();
}
function sendHwZoom(z) {
  if (zoomAnim.hwBusy) { zoomAnim.hwNext = z; return; }  // camera still busy: remember only the newest value
  const t = state.track; if (!t?.applyConstraints) return;
  zoomAnim.hwBusy = true;
  t.applyConstraints({ advanced: [{ zoom: z }] }).catch(() => {}).finally(() => {
    zoomAnim.hwBusy = false;
    if (zoomAnim.hwNext !== null) { const n = zoomAnim.hwNext; zoomAnim.hwNext = null; sendHwZoom(n); }
  });
}
/** Digital zoom: keep the enlarged picture inside the photo area (it must not spill into the black bars). */
function clipZoomedVideo() {
  const v = $('video'), z = digitalZoom();
  if (z <= 1 || !previewRect.w) { v.style.clipPath = ''; return; }
  const W = window.innerWidth, H = window.innerHeight;
  const hw = previewRect.w / 2 / z, hh = previewRect.h / 2 / z;
  v.style.clipPath = `inset(${Math.max(0, H / 2 - hh)}px ${Math.max(0, W / 2 - hw)}px ${Math.max(0, H / 2 - hh)}px ${Math.max(0, W / 2 - hw)}px)`;
}
/** The saved photo matches the zoomed view: keep the middle 1/zoom of the picture, at full size. */
function digitalCrop(img) {
  const z = digitalZoom();
  if (z <= 1) return img;
  const w = img.width, h = img.height, cw = w / z, ch = h / z;
  const c = document.createElement('canvas'); c.width = w; c.height = h;
  const ctx = c.getContext('2d'); ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(img, (w - cw) / 2, (h - ch) / 2, cw, ch, 0, 0, w, h);
  img.close?.();
  return c;
}
/* Two fingers on the camera screen = zoom the camera */
const pinch = { pts: new Map(), startDist: 0, startZoom: 1 };
function pinchDist() { const [a, b] = [...pinch.pts.values()]; return Math.hypot(a.x - b.x, a.y - b.y) || 1; }
function wirePinchZoom() {
  const cam = $('cam');
  cam.addEventListener('pointerdown', (e) => {
    if (e.pointerType === 'mouse') return;
    pinch.pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch.pts.size === 2) { pinch.startDist = pinchDist(); pinch.startZoom = zoomAnim.target || 1; }
  });
  cam.addEventListener('pointermove', (e) => {
    if (!pinch.pts.has(e.pointerId)) return;
    pinch.pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch.pts.size === 2 && state.stream) applyZoom(pinch.startZoom * (pinchDist() / pinch.startDist));
  });
  const end = (e) => { pinch.pts.delete(e.pointerId); if (pinch.pts.size < 2) pinch.startDist = 0; };
  cam.addEventListener('pointerup', end); cam.addEventListener('pointercancel', end); cam.addEventListener('pointerleave', end);
  // Computer: Ctrl + mouse wheel zooms the camera
  cam.addEventListener('wheel', (e) => { if (!e.ctrlKey || !state.stream) return; e.preventDefault(); applyZoom((zoomAnim.target || 1) * (e.deltaY < 0 ? 1.1 : 0.9)); }, { passive: false });
  $('zoomPill').addEventListener('click', () => applyZoom(1));
}
/* The app screen itself never zooms (iPhone ignores the page setting, so stop its zoom gestures too) */
function blockPageZoom() {
  ['gesturestart', 'gesturechange', 'gestureend'].forEach((t) => document.addEventListener(t, (e) => e.preventDefault(), { passive: false }));
  document.addEventListener('touchmove', (e) => { if (e.touches.length > 1) e.preventDefault(); }, { passive: false });
  // (double-tap zoom is switched off by the page style "touch-action: manipulation", so quick taps on the shutter still work)
  document.addEventListener('wheel', (e) => { if (e.ctrlKey && !e.target.closest('#cam')) e.preventDefault(); }, { passive: false });
}

function camFail(msg) { $('camErrorMsg').textContent = msg; $('camError').hidden = false; $('rotateHint').hidden = true; }

function setMode(mode, silent) {
  if (state.rec) return;
  const changed = state.mode !== mode;
  state.mode = mode;
  document.querySelectorAll('.mode-switch button').forEach((b) => b.setAttribute('aria-selected', b.dataset.mode === mode));
  $('shutter').classList.toggle('video', mode === 'video');
  $('shutter').setAttribute('aria-label', mode === 'video' ? 'Start recording' : 'Take photo');
  if (changed && !silent && state.screen === 'cam') startCamera();
  updateOrientation();
}

/* Live preview of the stamp exactly over the camera image */
let previewRect = { x: 0, y: 0, w: 0, h: 0 };
function layoutPreview() {
  const v = $('video'), c = $('preview');
  const vw = v.videoWidth, vh = v.videoHeight, W = window.innerWidth, H = window.innerHeight;
  if (!vw || !vh) return;
  const s = Math.min(W / vw, H / vh);                  // object-fit: contain
  previewRect = { w: vw * s, h: vh * s, x: (W - vw * s) / 2, y: (H - vh * s) / 2 };
  clipZoomedVideo();
  const dpr = window.devicePixelRatio || 1;
  Object.assign(c.style, { left: previewRect.x + 'px', top: previewRect.y + 'px', width: previewRect.w + 'px', height: previewRect.h + 'px' });
  c.width = Math.round(previewRect.w * dpr); c.height = Math.round(previewRect.h * dpr);
  drawPreview();
  updateOrientation();
}
function drawPreview() {
  if (state.screen !== 'cam' || !state.job) return;
  const c = $('preview'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  const stamp = buildStamp(state.type, new Date(), freshGps());
  // Admin's aspect ratio: darken what will be cut off, and put the stamp inside the part that is kept
  const a = aspectRect(c.width, c.height, aspectValue(state.mode));
  if (a.w < c.width - 1 || a.h < c.height - 1) {
    ctx.fillStyle = 'rgba(0,0,0,0.6)';
    ctx.fillRect(0, 0, c.width, a.y); ctx.fillRect(0, a.y + a.h, c.width, c.height - a.y - a.h);
    ctx.fillRect(0, a.y, a.x, a.h); ctx.fillRect(a.x + a.w, a.y, c.width - a.x - a.w, a.h);
    ctx.strokeStyle = 'rgba(255,255,255,0.7)'; ctx.lineWidth = Math.max(1, c.width / 400);
    ctx.strokeRect(a.x, a.y, a.w, a.h);
  }
  ctx.save(); ctx.translate(a.x, a.y);
  if (!sideCapture()) drawStamp(ctx, a.w, a.h, stamp);
  else {
    // Phone held sideways on an upright screen: draw the stamp as it will sit on the landscape photo, turned to match
    const off = document.createElement('canvas'); off.width = a.h; off.height = a.w;
    drawStamp(off.getContext('2d'), off.width, off.height, stamp);
    if (sideDir > 0) { ctx.translate(a.w, 0); ctx.rotate(Math.PI / 2); } else { ctx.translate(0, a.h); ctx.rotate(-Math.PI / 2); }
    ctx.drawImage(off, 0, 0);
  }
  ctx.restore();
}

async function grabFrame() {
  if (state.imageCapture) {
    try {
      // Ask the camera for a still photo of the size we will keep — not 50 MP that would only be shrunk (much faster)
      let opts;
      try {
        const pc = await state.imageCapture.getPhotoCapabilities();
        if (pc?.imageWidth?.max) {
          const want = photoConf().max_dim || 4680;           // "Device best": the most the app can process (~16.4 MP)
          const r = pc.imageWidth.max / pc.imageHeight.max;
          const w = Math.min(pc.imageWidth.max, Math.max(pc.imageWidth.min || 0, r >= 1 ? want : Math.round(want * r)));
          opts = { imageWidth: w, imageHeight: Math.round(w / r) };
        }
      } catch {}
      try { return await state.imageCapture.takePhoto(opts); }
      catch (e) { if (!opts) throw e; return await state.imageCapture.takePhoto(); }   // camera refused that size: its default
    } catch (e) { console.warn('takePhoto failed, using video frame', e); }
  }
  return videoFrame();
}
async function videoFrame() {
  const v = $('video');
  if (!v.videoWidth) throw new Error('Camera not ready');
  const c = document.createElement('canvas');
  c.width = v.videoWidth; c.height = v.videoHeight;
  c.getContext('2d').drawImage(v, 0, 0);
  return await new Promise((res) => c.toBlob(res, 'image/jpeg', 0.95));
}
async function toBitmap(blob) {
  try { return await createImageBitmap(blob, { imageOrientation: 'from-image' }); } catch {}
  try { return await createImageBitmap(blob); } catch {}
  const url = URL.createObjectURL(blob);
  try { const img = new Image(); img.src = url; await img.decode(); return img; } finally { URL.revokeObjectURL(url); }
}
function baseMeta(kind, when, gps, stamp) {
  const d = currentDetails();
  return {
    uid: uuid(), kind,
    job_id: state.job.id, job_number: state.job.job_number, site_name: state.job.site_name,
    type: state.type,
    captured_at: when.toISOString(),
    test_name: state.type === 'Laboratory' ? d.test_name : d.field_test,
    location_name: state.type === 'Field' ? locationName() : '',
    custom_text: state.type === 'Field' ? d.custom_text : '',
    gps: gps ? { lat: gps.lat, lon: gps.lon, accuracy: gps.accuracy, altitude: gps.altitude } : null,
    coord_text: stamp.coordText,
    stamp_lines: stamp.lines,
    device: navigator.userAgent.slice(0, 200),
    app_version: APP_VERSION,
    photographer_name: state.auth?.shared ? state.photographer : '',
  };
}

async function onShutter() {
  if (state.mode === 'video') return state.rec ? stopRecording() : startRecording();
  if (state.busy) return;
  if (photoBlocked()) { updateOrientation(); toast('Turn your phone sideways — field photos are landscape only', true); navigator.vibrate?.([60, 40, 60]); return; }
  const miss = detailsMissing();
  if (miss) { toast('Choose the ' + miss + ' first'); openSheet('detailsSheet'); return; }
  state.busy = true; $('shutter').classList.add('busy');
  try {
    const f = $('flash'); f.classList.add('on'); requestAnimationFrame(() => requestAnimationFrame(() => f.classList.remove('on')));
    navigator.vibrate?.(30);
    try { await document.fonts?.load(`600 20px ${STAMP_FONT}`); } catch {}
    const when = new Date(), gps = freshGps();
    const turn = sideCapture() ? sideDir : 0;                 // phone held sideways, screen upright
    const raw = await grabFrame();
    let bmp = digitalCrop(await toBitmap(raw));          // pinch zoom (digital): keep the zoomed middle part
    if (turn && bmp.height > bmp.width) {
      // Camera-app style: turn the upright picture into the landscape photo the user is holding
      const rotated = rotateSideways(bmp, turn); bmp.close?.(); bmp = rotated;
    } else if (state.type === 'Field' && bmp.height > bmp.width) {   // camera returned an upright still — use the (landscape) live frame
      bmp.close?.(); bmp = digitalCrop(await toBitmap(await videoFrame()));
      if (bmp.height > bmp.width) { bmp.close?.(); throw new Error('Turn your phone sideways — field photos are landscape only'); }
    }
    bmp = aspectCrop(bmp, aspectValue('photo'));          // admin's aspect ratio (4:3, 3:2, 16:9)
    const stamp = buildStamp(state.type, when, gps);
    const meta = baseMeta('photo', when, gps, stamp);
    const sw = bmp.width, sh = bmp.height;
    const pc = photoConf();
    let scale = pc.max_dim ? Math.min(1, pc.max_dim / Math.max(sw, sh)) : 1;
    // Phones can't draw images above ~16.7 million pixels on a canvas (iPhone limit); stay just under it
    const MAX_PIXELS = 16.5e6;
    if (sw * sh * scale * scale > MAX_PIXELS) scale = Math.sqrt(MAX_PIXELS / (sw * sh));
    const w = Math.round(sw * scale), h = Math.round(sh * scale);
    const c = document.createElement('canvas'); c.width = w; c.height = h;
    const ctx = c.getContext('2d');
    ctx.drawImage(bmp, 0, 0, w, h);
    bmp.close?.();
    meta.stamp_lines = drawStamp(ctx, w, h, stamp);
    const blob = await new Promise((res) => c.toBlob(res, 'image/jpeg', pc.quality));
    c.width = c.height = 0;
    if (!blob) throw new Error('Could not create photo');
    meta.width = w; meta.height = h;
    if (pc.review) {
      state.pending = { blob, meta, url: URL.createObjectURL(blob) };
      $('reviewImg').src = state.pending.url;
      $('review').hidden = false;
      pushNav();
    } else {
      await savePhoto(blob, meta);
    }
  } catch (e) {
    toast(e.message || 'Capture failed', true);
  } finally {
    state.busy = false; $('shutter').classList.remove('busy');
  }
}
function endReview() {
  setTimeout(updateOrientation, 0);
  if (state.pending) URL.revokeObjectURL(state.pending.url);
  $('reviewImg').removeAttribute('src');
  state.pending = null;
  $('review').hidden = true;
}
/* ======================= upload photos from the phone (taken earlier with another camera) ======================= */
const upload = { files: [], type: 'Field', coordMode: 'latlon', urls: [] };
const pad2s = (n) => String(n).padStart(2, '0');
function toLocalInput(d) { return `${d.getFullYear()}-${pad2s(d.getMonth() + 1)}-${pad2s(d.getDate())}T${pad2s(d.getHours())}:${pad2s(d.getMinutes())}`; }
function onUploadFiles(e) {
  const files = [...(e.target.files || [])].filter((f) => /^image\//.test(f.type) || /\.(jpe?g|png|heic|webp)$/i.test(f.name));
  e.target.value = '';
  if (!files.length) return;
  upload.files = files;
  upload.type = state.type || 'Field';
  $('upWhen').value = toLocalInput(new Date(files[0].lastModified || Date.now()));   // when the photo was taken (best guess)
  $('upTest').value = ''; $('upText').value = currentDetails().custom_text || '';
  ['upLat', 'upLon', 'upZone', 'upBand', 'upE', 'upN'].forEach((id) => { $(id).value = ''; });
  openSheet('uploadSheet');
}
function renderUpload() {
  upload.urls.forEach(URL.revokeObjectURL);
  upload.urls = upload.files.slice(0, 12).map((f) => URL.createObjectURL(f));
  $('upThumbs').innerHTML = upload.urls.map((u) => `<img src="${u}" alt="">`).join('')
    + (upload.files.length > 12 ? `<span class="muted small">+${upload.files.length - 12} more</span>` : '');
  renderUploadForm(true);
}
function renderUploadForm(rebuildList) {
  const lab = upload.type === 'Laboratory', conf = stampConf(upload.type);
  $('upType').querySelectorAll('[data-type]').forEach((b) => b.setAttribute('aria-checked', b.dataset.type === upload.type));
  $('upTestLabel').textContent = lab ? 'Test name' : 'Field test name';
  $('upTestReq').hidden = !conf.test_name;
  if (rebuildList) {
    const d = currentDetails(), cur = lab ? d.test_name : d.field_test;
    const names = (lab ? state.settings?.test_names : state.settings?.field_test_names) || [];
    $('upTestSel').innerHTML = `<option value="">— Select ${lab ? 'test' : 'field test'} —</option>`
      + names.map((n) => `<option value="${esc(n)}" ${n === cur ? 'selected' : ''}>${esc(n)}</option>`).join('')
      + '<option value="__other">Other (type it)</option>';
  }
  $('upTestOtherRow').hidden = $('upTestSel').value !== '__other';
  $('upFieldOnly').hidden = lab;
  $('upCoordBox').hidden = lab || !conf.coords;
  $('upCoordMode').querySelectorAll('[data-mode]').forEach((b) => b.setAttribute('aria-checked', b.dataset.mode === upload.coordMode));
  $('upLatLon').hidden = upload.coordMode !== 'latlon';
  $('upUtm').hidden = upload.coordMode !== 'utm';
  const c = readUploadCoords();
  $('upCoordPreview').textContent = c.error ? '' : c.text ? 'On the photo: ' + c.text : '';
  $('upGo').textContent = `Stamp & upload ${upload.files.length} photo${upload.files.length === 1 ? '' : 's'}`;
  $('upErr').textContent = '';
}
/** Coordinates typed in → { gps, text } in the company's stamp format, or { error }. */
function readUploadCoords() {
  const fmt = stampConf('Field').coord_format || 'utm', num = (id) => Number(String($(id).value).replace(',', '.').trim());
  if (upload.coordMode === 'latlon') {
    if (!$('upLat').value.trim() && !$('upLon').value.trim()) return { empty: true };
    const lat = num('upLat'), lon = num('upLon');
    if (!isFinite(lat) || lat < -90 || lat > 90 || !isFinite(lon) || lon < -180 || lon > 180) return { error: 'Latitude must be −90 to 90 and longitude −180 to 180 (decimal degrees, e.g. 22.303900).' };
    return { gps: { lat, lon, accuracy: null, altitude: null }, text: fmtCoords(lat, lon, fmt) };
  }
  if (!['upZone', 'upBand', 'upE', 'upN'].some((id) => $(id).value.trim())) return { empty: true };
  const zone = num('upZone'), band = $('upBand').value.trim().toUpperCase(), E = num('upE'), N = num('upN');
  if (!(zone >= 1 && zone <= 60 && Number.isInteger(zone)) || !/^[C-HJ-NP-X]$/.test(band) || !(E >= 100000 && E <= 900000) || !(N >= 0 && N <= 10000000)) {
    return { error: 'UTM: zone 1–60, band letter (e.g. Q), easting 100000–900000 m, northing 0–10000000 m.' };
  }
  const ll = fromUTM(zone, band, E, N);
  const text = fmt === 'utm' ? `${zone} ${band} ${Math.round(E)} m E ${Math.round(N)} m N` : fmtCoords(ll.lat, ll.lon, fmt);
  return { gps: { lat: ll.lat, lon: ll.lon, accuracy: null, altitude: null }, text };
}
async function submitUpload(e) {
  e.preventDefault();
  const lab = upload.type === 'Laboratory', conf = stampConf(upload.type);
  const sel = $('upTestSel').value, test = sel === '__other' ? $('upTest').value.trim() : sel;
  if (conf.test_name && !test) { $('upErr').textContent = `Please choose the ${lab ? 'test' : 'field test'} name`; return; }
  let coords = { empty: true };
  if (!lab && conf.coords) {
    coords = readUploadCoords();
    if (coords.error) { $('upErr').textContent = coords.error; return; }
    if (coords.empty) { $('upErr').textContent = 'Please type the coordinates of the place where the photos were taken'; return; }
  }
  const when = $('upWhen').value ? new Date($('upWhen').value) : new Date();
  if (isNaN(when)) { $('upErr').textContent = 'Please enter the date and time'; return; }
  const details = lab ? { test_name: test } : { field_test: test, custom_text: $('upText').value.trim() };
  const btn = $('upGo'); btn.disabled = true;
  let done = 0;
  try {
    try { await document.fonts?.load(`600 20px ${STAMP_FONT}`); } catch {}
    const pc = photoConf();
    for (const file of upload.files) {
      btn.textContent = `Stamping ${done + 1} of ${upload.files.length}…`;
      const bmp = await toBitmap(file);
      const sw = bmp.width, sh = bmp.height;
      let scale = pc.max_dim ? Math.min(1, pc.max_dim / Math.max(sw, sh)) : 1;
      if (sw * sh * scale * scale > 16.5e6) scale = Math.sqrt(16.5e6 / (sw * sh));
      const w = Math.round(sw * scale), h = Math.round(sh * scale);
      const c = document.createElement('canvas'); c.width = w; c.height = h;
      const ctx = c.getContext('2d'); ctx.drawImage(bmp, 0, 0, w, h); bmp.close?.();
      const stamp = buildStamp(upload.type, when, coords.gps || null, { details, coordText: coords.text || '' });
      const meta = baseMeta('photo', when, coords.gps || null, stamp);
      Object.assign(meta, {
        type: upload.type, test_name: test, source: 'upload',
        custom_text: lab ? '' : details.custom_text, location_name: lab ? '' : locationName(),
        stamp_lines: drawStamp(ctx, w, h, stamp), width: w, height: h,
      });
      const blob = await new Promise((res) => c.toBlob(res, 'image/jpeg', pc.quality));
      c.width = c.height = 0;
      if (!blob) throw new Error('Could not read ' + file.name);
      await savePhoto(blob, meta, { noLocal: true, quiet: true });
      done++;
    }
    // remember the choice for the next photos of this job
    const d = currentDetails(); if (lab) d.test_name = test; else { d.field_test = test; d.custom_text = details.custom_text; }
    kvSet('jobDetails', state.jobDetails);
    closeSheet();
    toast(`${done} photo${done === 1 ? '' : 's'} stamped — uploading…`);
  } catch (err) {
    $('upErr').textContent = (err && err.message ? err.message : 'Could not read the photo') + (done ? ` (${done} already saved)` : '');
  } finally { btn.disabled = false; renderUploadForm(false); }
}

/* ---------- optional copy of Field photos on this phone (per-job switch) ---------- */
function localName(meta) {
  const d = new Date(meta.captured_at), safe = (s) => String(s || '').replace(/[\\/:*?"<>|]+/g, '_').trim();
  const stamp = `${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}-${pad2(d.getHours())}${pad2(d.getMinutes())}${pad2(d.getSeconds())}`;
  return `${safe(meta.job_number)}-${safe(meta.test_name) || 'Field'}-${stamp}.jpg`;
}
async function saveToPhone(blob, name) {
  // Android app: straight into the gallery (Pictures/FieldCam), sent in pieces
  if (ANDROID_APP) {
    if (typeof ANDROID_APP.saveBegin !== 'function') { toast('Update the FieldCam Android app to save photos on the phone', true, 4000); return false; }
    const buf = new Uint8Array(await blob.arrayBuffer());
    const id = ANDROID_APP.saveBegin(name);
    if (!id) { toast('Allow “Photos/Storage” for FieldCam to save on the phone', true, 4000); return false; }
    for (let i = 0; i < buf.length; i += 768 * 1024) ANDROID_APP.saveAppend(id, toB64(buf.subarray(i, i + 768 * 1024)));
    const res = ANDROID_APP.saveFinish(id);
    if (res !== 'ok') { toast('Could not save on the phone: ' + res, true, 4000); return false; }
    return true;
  }
  // Browser: download a copy (Android Chrome: Downloads; iPhone: offers to save)
  const url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  return true;
}
async function savePhoto(blob, meta, opts = {}) {
  // Admin switched on "Save Field photos on phones too" for this job (New / Edit job); not for photos uploaded from the phone
  if (!opts.noLocal && meta.type === 'Field' && state.job?.save_local) {
    try { await saveToPhone(blob, localName(meta)); } catch (e) { toast('Could not save on the phone', true); }
  }
  const buf = await blob.arrayBuffer();
  const total = Math.max(1, Math.ceil(buf.byteLength / CHUNK));
  for (let i = 0; i < total; i++) await chunkPut(meta.uid, i, await seal(buf.slice(i * CHUNK, (i + 1) * CHUNK)));
  await qPut({ uid: meta.uid, kind: 'photo', ext: 'jpg', meta, total, sent: 0, complete: true, created: Date.now(), size: buf.byteLength, status: 'pending', error: '' });
  refreshBadge();
  if (!opts.quiet) toast(navigator.onLine ? 'Saved — uploading…' : 'Saved — will upload when online');
  syncQueue();
}

/* ======================= video ======================= */
function pickVideoType() {
  const cands = [
    ['video/mp4;codecs=avc1.42E01E,mp4a.40.2', 'mp4'], ['video/mp4;codecs=avc1', 'mp4'], ['video/mp4', 'mp4'],
    ['video/webm;codecs=vp9,opus', 'webm'], ['video/webm;codecs=vp8,opus', 'webm'], ['video/webm', 'webm'],
  ];
  if (!window.MediaRecorder) return null;
  for (const [m, ext] of cands) if (MediaRecorder.isTypeSupported?.(m)) return { mime: m, ext };
  return { mime: '', ext: 'mp4' };
}
async function startRecording() {
  const miss = detailsMissing();
  if (miss) { toast('Choose the ' + miss + ' first'); openSheet('detailsSheet'); return; }
  const vt = pickVideoType();
  if (!vt || !HTMLCanvasElement.prototype.captureStream) { toast('This phone/browser cannot record video in the app', true); return; }
  if (state.streamMode !== 'video') await startCamera();
  const v = $('video');
  if (!v.videoWidth) { toast('Camera not ready', true); return; }
  try {
    const est = await navigator.storage?.estimate?.();
    if (est && est.quota - est.usage < 300 * 1048576) toast('Phone storage is low — keep the video short', true, 4000);
  } catch {}

  const maxRes = state.settings?.video?.max_res || Infinity;   // 0 = device best (no limit)
  const r0 = v.videoWidth / v.videoHeight, vAspect = aspectValue('video');   // admin's aspect ratio for videos
  const crop0 = aspectRect(v.videoWidth, v.videoHeight, vAspect);
  const sc = Math.min(1, maxRes / Math.max(crop0.w, crop0.h));
  const W = Math.round(crop0.w * sc / 2) * 2, H = Math.round(crop0.h * sc / 2) * 2;
  const canvas = document.createElement('canvas'); canvas.width = W; canvas.height = H;
  const ctx = canvas.getContext('2d');
  const layer = document.createElement('canvas'); layer.width = W; layer.height = H;
  const lctx = layer.getContext('2d');
  const started = new Date(), gps0 = freshGps();
  const stamp0 = buildStamp(state.type, started, gps0);
  const meta = baseMeta('video', started, gps0, stamp0);
  meta.width = W; meta.height = H;

  const refreshLayer = () => { lctx.clearRect(0, 0, W, H); drawStamp(lctx, W, H, buildStamp(state.type, new Date(), freshGps())); };
  refreshLayer();

  const out = canvas.captureStream(30);
  state.stream.getAudioTracks().forEach((t) => out.addTrack(t));
  const bps = Math.round(Math.max(2.5e6, Math.min(24e6, W * H * 30 * 0.13)));   // ~8 Mbps at 1080p, ~24 Mbps at 4K
  let recorder;
  try { recorder = new MediaRecorder(out, vt.mime ? { mimeType: vt.mime, videoBitsPerSecond: bps } : { videoBitsPerSecond: bps }); }
  catch (e) { toast('Could not start recording: ' + e.message, true); return; }
  const ext = (recorder.mimeType || vt.mime).includes('webm') ? 'webm' : 'mp4';

  const rec = { uid: meta.uid, meta, ext, recorder, canvas, buf: [], bufSize: 0, idx: 0, size: 0, started: Date.now(), saving: Promise.resolve(), timers: [] };
  state.rec = rec;
  await qPut({ uid: meta.uid, kind: 'video', ext, meta, total: 0, sent: 0, complete: false, created: Date.now(), size: 0, status: 'recording', error: '' });

  // Save pieces to encrypted storage as they arrive, so long videos never sit in memory
  const flush = (final) => {
    rec.saving = rec.saving.then(async () => {
      if (!rec.bufSize) return;
      let blob = new Blob(rec.buf);
      rec.buf = []; rec.bufSize = 0;
      let off = 0;
      while (blob.size - off >= CHUNK || (final && off < blob.size)) {
        const part = await blob.slice(off, off + CHUNK).arrayBuffer();
        await chunkPut(rec.uid, rec.idx++, await seal(part));
        rec.size += part.byteLength; off += part.byteLength;
      }
      if (off < blob.size) { const rest = blob.slice(off); rec.buf.push(rest); rec.bufSize = rest.size; }
    }).catch((e) => { toast('Saving video failed: ' + e.message, true); });
    return rec.saving;
  };
  recorder.ondataavailable = (e) => {
    if (!e.data?.size) return;
    rec.buf.push(e.data); rec.bufSize += e.data.size;
    if (rec.bufSize >= CHUNK) flush(false);
  };
  recorder.onstop = async () => {
    await flush(true);
    rec.timers.forEach(clearInterval);
    const dur = (Date.now() - rec.started) / 1000;
    meta.duration_s = Math.round(dur * 10) / 10;
    await qPut({ uid: meta.uid, kind: 'video', ext, meta, total: rec.idx, sent: 0, complete: rec.idx > 0, created: rec.started, size: rec.size, status: 'pending', error: '' });
    if (!rec.idx) await qRemove(meta.uid);
    state.rec = null;
    $('shutter').classList.remove('recording');
    $('recTimer').hidden = true;
    document.querySelector('.mode-switch').classList.remove('locked');
    drawPreview(); refreshBadge();
    toast(`Video saved (${Math.round(dur)} s, ${fmtBytes(rec.size)}) — ${navigator.onLine ? 'uploading…' : 'will upload when online'}`);
    syncQueue();
  };

  // Draw camera + stamp onto the recording canvas
  let alive = true;
  rec.stopDraw = () => { alive = false; };
  const draw = () => {
    if (!alive) return;
    const vw = v.videoWidth, vh = v.videoHeight;
    const dz = digitalZoom();                            // pinch zoom (digital) also applies to videos
    if (Math.abs(vw / vh - r0) < 0.02) {                // same way up as when recording started: keep the chosen shape (+ zoom)
      const a = aspectRect(vw, vh, vAspect);
      ctx.drawImage(v, a.x + (a.w - a.w / dz) / 2, a.y + (a.h - a.h / dz) / 2, a.w / dz, a.h / dz, 0, 0, W, H);
    }
    else {                                          // phone turned while recording: fit without stretching
      const k = Math.min(W / vw, H / vh);
      ctx.fillStyle = '#000'; ctx.fillRect(0, 0, W, H);
      ctx.drawImage(v, (W - vw * k) / 2, (H - vh * k) / 2, vw * k, vh * k);
    }
    ctx.drawImage(layer, 0, 0);
    if (v.requestVideoFrameCallback) v.requestVideoFrameCallback(draw); else requestAnimationFrame(draw);
  };
  draw();
  rec.timers.push(setInterval(refreshLayer, 1000));
  rec.timers.push(setInterval(() => {
    const s = Math.floor((Date.now() - rec.started) / 1000);
    $('recTimer').querySelector('span').textContent = `${pad2(Math.floor(s / 60))}:${pad2(s % 60)}`;
    if (s >= MAX_VIDEO_SEC) { toast('Maximum video length reached'); stopRecording(); }
  }, 500));

  recorder.start(1000);
  navigator.vibrate?.(40);
  $('shutter').classList.add('recording');
  $('shutter').setAttribute('aria-label', 'Stop recording');
  $('recTimer').hidden = false; $('recTimer').querySelector('span').textContent = '00:00';
  document.querySelector('.mode-switch').classList.add('locked');
  drawPreview();
}
function stopRecording() {
  const rec = state.rec; if (!rec || rec.stopping) return;
  rec.stopping = true;
  rec.stopDraw?.();
  $('shutter').setAttribute('aria-label', 'Start recording');
  try { rec.recorder.state !== 'inactive' ? rec.recorder.stop() : rec.recorder.onstop(); } catch { rec.recorder.onstop?.(); }
  navigator.vibrate?.([30, 60, 30]);
}

/* ======================= upload queue ======================= */
async function uploadRecord(rec) {
  let conflicts = 0;
  while (rec.sent < rec.total) {
    const c = await chunkGet(rec.uid, rec.sent);
    if (!c) { rec.status = 'error'; rec.error = 'Part of this file is missing on the phone'; await qPut(rec); return 'error'; }
    const data = await unseal(c);
    const last = rec.sent === rec.total - 1;
    const fd = new FormData();
    fd.append('uid', rec.uid); fd.append('idx', rec.sent); fd.append('total', rec.total);
    fd.append('kind', rec.kind); fd.append('ext', rec.ext);
    if (last) fd.append('meta', JSON.stringify(rec.meta));
    fd.append('chunk', new Blob([data]), 'part');
    const r = await api('upload.php', { body: fd, timeout: 120000 });
    if (r.status === 401) return 'auth';
    if (r.ok) {
      if (r.done) { await qRemove(rec.uid); return 'done'; }   // NAS confirmed — remove from phone
      rec.sent = typeof r.next === 'number' ? r.next : rec.sent + 1;
      rec.status = 'uploading'; rec.error = '';
      await qPut(rec); updateQueueRow(rec);
      continue;
    }
    if (r.status === 409 && typeof r.next === 'number' && ++conflicts < 6) { rec.sent = r.next; await qPut(rec); continue; }
    rec.status = 'error'; rec.error = r.error || 'Upload failed';
    await qPut(rec);
    return r.status === 0 ? 'offline' : 'error';
  }
  return 'done';
}
async function syncQueue() {
  if (state.syncing || !state.auth || !navigator.onLine) return;
  state.syncing = true; renderNet();
  try {
    const items = (await qAll()).filter((r) => r.complete).sort((a, b) => a.created - b.created);
    // two photos/videos upload at the same time (faster on good networks)
    let next = 0, stop = false;
    const worker = async () => {
      while (!stop && next < items.length) {
        const res = await uploadRecord(items[next++]);
        refreshBadge();
        if (res === 'auth' || res === 'offline') stop = true;
      }
    };
    await Promise.all([worker(), worker()]);
  } catch (e) { console.warn('sync', e); }
  finally {
    state.syncing = false;
    renderNet(); refreshBadge();
    if (openSheetId === 'queueSheet') renderQueue();
  }
}
async function refreshBadge() {
  const all = (await qAll()).filter((r) => r.complete);
  document.querySelectorAll('[data-queue-badge]').forEach((b) => {
    b.hidden = !all.length; b.textContent = all.length;
    b.classList.toggle('bad', all.some((r) => r.status === 'error'));
  });
}
let thumbUrls = [];
function revokeThumbs() { thumbUrls.forEach(URL.revokeObjectURL); thumbUrls = []; }
function queueStatus(r) {
  if (!r.complete) return 'recording…';
  if (r.status === 'error') return esc(r.error);
  if (r.status === 'uploading' || r.sent) return `uploading ${Math.round((r.sent / r.total) * 100)}%`;
  return 'waiting';
}
function updateQueueRow(r) {
  const s = openSheetId === 'queueSheet' && $('queueList').querySelector(`[data-uid="${r.uid}"] .s`);
  if (s) s.innerHTML = `${new Date(r.created).toLocaleString('en-IN', { hour12: false })} · ${queueStatus(r)}`;
}
async function renderQueue() {
  revokeThumbs();
  const items = (await qAll()).sort((a, b) => a.created - b.created);
  const total = items.reduce((s, r) => s + (r.size || 0), 0);
  $('queueSummary').textContent = items.length
    ? `${items.length} waiting · ${fmtBytes(total)}${navigator.onLine ? '' : ' · offline'}`
    : `Everything is ${GAS_URL ? 'in' : 'on'} ${STORE_THE}. Nothing is stored on this phone.`;
  $('syncNow').hidden = !items.length;
  $('queueList').innerHTML = items.map((r) => `
    <li data-uid="${r.uid}">
      <div class="ph">${r.kind === 'video' ? '🎬' : ''}</div>
      <div><div class="t">${esc(r.meta.job_number)} · ${r.meta.type === 'Laboratory' ? 'Lab' : 'Field'} ${r.kind === 'video' ? 'video' : 'photo'}</div>
        <div class="s ${r.status === 'error' ? 'bad' : ''}">${new Date(r.created).toLocaleString('en-IN', { hour12: false })} · ${queueStatus(r)}</div></div>
      ${r.complete ? '<button class="del" aria-label="Delete">🗑</button>' : ''}
    </li>`).join('');
  for (const r of items) {
    if (r.kind !== 'photo') continue;
    try {
      const parts = [];
      for (let i = 0; i < r.total; i++) parts.push(await unseal(await chunkGet(r.uid, i)));
      const url = URL.createObjectURL(new Blob(parts, { type: 'image/jpeg' })); thumbUrls.push(url);
      const ph = $('queueList').querySelector(`[data-uid="${r.uid}"] .ph`);
      if (ph) ph.outerHTML = `<img src="${url}" alt="">`;
    } catch {}
  }
}
async function onQueueClick(e) {
  const btn = e.target.closest('.del'); if (!btn) return;
  const uid = btn.closest('li').dataset.uid;
  if (!confirm(`This has NOT reached ${STORE_THE}. Delete it permanently from the phone?`)) return;
  await qRemove(uid); refreshBadge(); renderQueue();
}

/* ======================= settings ======================= */
function renderSettings() {
  const admin = state.auth?.role === 'admin';
  $('whoami').textContent = `${state.auth?.name} (${state.auth?.user})${admin ? ' · Admin' : ''}${state.auth?.shared ? ' · shared login' : ''}`;
  $('photogRow').hidden = !state.auth?.shared;
  $('photogName').textContent = state.photographer || '—';
  $('adminBtn').hidden = !admin;
  $('staffNote').hidden = admin;
  $('changeNasBtn').hidden = !ANDROID_APP;
  $('appVer').textContent = 'FieldCam ' + APP_VERSION + (ANDROID_APP ? ' · Android app ' + ANDROID_APP.version() : ' · browser') + '\n' + screenInfo();
  checkServer();
}
async function checkServer() {
  const box = $('serverBox');
  box.textContent = `Checking ${STORE}…`;
  const r = await loadBootstrap();
  if (!r?.ok) { box.innerHTML = `<div style="color:var(--bad)">${STORE} not reachable: ${esc(r?.error)}</div>`; return; }
  const row = (ok, text) => `<div style="color:var(--${ok ? 'ok' : 'bad'})">${ok ? '✓' : '✗'} ${esc(text)}</div>`;
  box.innerHTML = [
    row(true, `Connected to ${STORE}`),
    row(r.storage_writable, r.storage_exists ? (r.storage_writable ? 'Testing Photographs folder is writable' : 'Folder exists but is NOT writable') : `Testing Photographs folder not found in ${STORE}`),
    r.role === 'admin' ? row(!r.secret_is_default, r.secret_is_default ? 'Change the secret in api/config.php' : 'Security key set') : '',
  ].join('');
}

/** Settings diagnostic: what this phone reports (screen width, layout width, scaling, text enlargement). */
function screenInfo() {
  let text = '?';
  try {
    const s = document.createElement('span');
    s.style.cssText = 'position:absolute;visibility:hidden;white-space:nowrap;font:16px "Roboto Condensed";letter-spacing:0';
    s.textContent = 'FieldCam text check 0123456789';
    document.body.appendChild(s); text = Math.round(s.getBoundingClientRect().width / 210.47 * 100); s.remove();
  } catch {}
  const sw = Math.min(screen.width, screen.height);
  return `screen ${sw} · layout ${window.innerWidth} · ×${(window.visualViewport?.scale || 1).toFixed(2)} · text ${text}%`;
}

/* ======================= admin: company settings ======================= */
function colourRow(label, key, swatches, value) {
  return `<label class="toggle-row">${label}<span class="swatches">${swatches.map((x) =>
      `<button type="button" data-swatch-k="${key}" data-c="${x}" style="background:${x}" class="${x === value ? 'on' : ''}" aria-label="${x}"></button>`).join('')}
      <input type="color" data-k="${key}" value="${value}" aria-label="Custom colour"></span></label>`;
}
function styleRows(g, c) {
  const st = stampStyle(c);
  return colourRow('Font colour', `${g}.text_color`, SWATCHES, st.color)
    + selectRow('Font size', `${g}.text_size`, TEXT_SIZES, st.size)
    + selectRow('Background', `${g}.band`, BANDS, st.band)
    + `<div class="bg-rows" data-bg-for="${g}" ${st.band === 'none' ? 'hidden' : ''}>`
    + colourRow('Background colour', `${g}.bg_color`, BG_SWATCHES, st.bg)
    + `<label class="toggle-row">Background opacity<span class="range"><input type="range" min="0" max="100" step="5" data-k="${g}.bg_opacity" value="${st.opacity}"><output>${st.opacity}%</output></span></label>`
    + `</div>`
    + `<p class="muted small">Max 3 lines per column — more lines move into a second column.</p>`
    + `<canvas class="stamp-sample" data-sample="${g}"></canvas>`;
}
/** Small live sample of the stamp inside Admin settings */
function drawSamples() {
  document.querySelectorAll('#adminSheet [data-sample]').forEach((cv) => {
    const g = cv.dataset.sample, conf = {};
    document.querySelectorAll(`#adminSheet [data-k^="${g}."]`).forEach((el) => { conf[el.dataset.k.split('.')[1]] = el.type === 'checkbox' ? el.checked : el.value; });
    const dpr = window.devicePixelRatio || 1, W = cv.clientWidth || 300;
    const Hc = Math.round(W * 0.5625);                  // full 16:9 photo, so the logo is visible too
    cv.width = W * dpr; cv.height = Hc * dpr; cv.style.height = Hc + 'px';
    const ctx = cv.getContext('2d');
    const grd = ctx.createLinearGradient(0, 0, cv.width, cv.height);
    grd.addColorStop(0, '#6b8f5a'); grd.addColorStop(1, '#b8a47a');
    ctx.fillStyle = grd; ctx.fillRect(0, 0, cv.width, cv.height);
    const lines = g === 'lab'
      ? ['Sub-Job No: JN-2026/045', 'Project: Rajkot Ring Road Bridge', 'Test: Cube Compressive Strength', '27 September, 2026 | 02:30 PM']
      : ['27 September, 2026 | 02:30 PM', fmtCoords(22.3039, 70.8022, conf.coord_format || 'utm'), 'Madhapar, Rajkot, Gujarat', 'Project: Rajkot Ring Road Bridge', 'Test: Plate Load Test'];
    const logoOn = g === 'field' && conf.logo !== false && !!state.logo;
    drawStamp(ctx, cv.width, cv.height, { lines, style: stampStyle(conf), logo: logoOn, corner: conf.logo_corner || 'top-left', logoSize: conf.logo_size, logoOpacity: conf.logo_opacity });
  });
}
function renderAdmin() {
  const s = state.settings;
  if (!s) { $('adminErr').textContent = `Connect to ${STORE_THE} first.`; return; }
  $('aLab').innerHTML = toggleRows(LAB_ITEMS, s.lab, 'lab.') + styleRows('lab', s.lab);
  $('aField').innerHTML = toggleRows(FIELD_ITEMS, s.field, 'field.')
    + selectRow('Coordinate format', 'field.coord_format', COORD_FORMATS, s.field.coord_format)
    + selectRow('Logo corner', 'field.logo_corner', CORNERS, s.field.logo_corner)
    + `<label class="toggle-row">Logo size<span class="range"><input type="range" min="10" max="60" step="2" data-k="field.logo_size" value="${s.field.logo_size || 26}"><output>${s.field.logo_size || 26}%</output></span></label>`
    + `<label class="toggle-row">Logo opacity<span class="range"><input type="range" min="10" max="100" step="5" data-k="field.logo_opacity" value="${s.field.logo_opacity ?? 100}"><output>${s.field.logo_opacity ?? 100}%</output></span></label>`
    + styleRows('field', s.field);
  // Test lists: a drop-down per list, "+" to add a test, bin to remove the selected one
  adminLists = { test_names: [...(s.test_names || [])], field_test_names: [...(s.field_test_names || [])] };
  renderTestList('test_names'); renderTestList('field_test_names');
  const pc = photoConf();
  // Older settings used 4000 / 3000 / 2000 px — show the nearest of today's sizes
  const oldPhoto = { 4000: 3840, 3000: 2560, 2000: 1920 };
  $('aMax').value = String(oldPhoto[pc.max_dim] ?? pc.max_dim);
  $('aQuality').value = String(pc.quality);
  if (!$('aQuality').value) $('aQuality').value = '0.85';
  $('aReview').checked = !!pc.review;
  $('aPhotoAspect').value = pc.aspect || '';
  $('aVideoAspect').value = s.video?.aspect || '';
  const vr = s.video?.max_res ?? 0;
  $('aVideoRes').value = String(vr === 720 ? 854 : vr);
  $('aAudio').checked = s.video?.audio !== false;
  $('adminErr').textContent = '';
  renderLogoBox();
  requestAnimationFrame(drawSamples);
}
/* ---------- admin: test name lists (drop-down + "+" to add, bin to remove) ---------- */
let adminLists = { test_names: [], field_test_names: [] };
function renderTestList(key, select) {
  const box = document.querySelector(`#adminSheet .test-edit[data-list="${key}"]`); if (!box) return;
  const list = adminLists[key];
  const sel = box.querySelector('.test-sel');
  const keep = select ?? sel.value;
  sel.innerHTML = list.length ? list.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join('') : '<option value="">(no tests yet — tap +)</option>';
  sel.value = list.includes(keep) ? keep : (list[0] || '');
  box.querySelector('.del').disabled = !list.length;
  box.querySelector('.count').textContent = `${list.length} test${list.length === 1 ? '' : 's'} in this list`;
}
function onTestListClick(e) {
  const box = e.target.closest('.test-edit'); if (!box) return;
  const key = box.dataset.list, addRow = box.querySelector('.test-add'), input = addRow.querySelector('input');
  if (e.target.closest('.add')) {
    addRow.hidden = !addRow.hidden;
    if (!addRow.hidden) { input.value = ''; input.focus(); }
  } else if (e.target.closest('.add-ok')) {
    const name = input.value.trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!name) { input.focus(); return; }
    const list = adminLists[key];
    if (list.some((t) => t.toLowerCase() === name.toLowerCase())) { toast('That test is already in the list', true); return; }
    list.push(name);
    addRow.hidden = true;
    renderTestList(key, name);
    toast(`Added “${name}” — tap Save for everyone`);
  } else if (e.target.closest('.del')) {
    const sel = box.querySelector('.test-sel'), name = sel.value; if (!name) return;
    askConfirm({ title: 'Remove this test?', html: `<p>“${esc(name)}” will no longer be in the drop-down for staff. Photos already taken are not changed.</p>`, yes: 'Remove' })
      .then((ok) => { if (!ok) return; adminLists[key] = adminLists[key].filter((t) => t !== name); renderTestList(key); });
  }
}

let logoUrl;
function renderLogoBox() {
  if (logoUrl) URL.revokeObjectURL(logoUrl), logoUrl = null;
  kvGet('logo').then((l) => {
    if (l?.data && state.settings?.logo_version) {
      logoUrl = URL.createObjectURL(new Blob([l.data], { type: 'image/png' }));
      $('logoBox').innerHTML = `<img src="${logoUrl}" alt="Company logo">`;
    } else $('logoBox').textContent = 'No logo';
    $('logoRemove').hidden = !state.settings?.logo_version;
  });
}
async function saveAdmin() {
  const s = { lab: {}, field: {}, video: {} };
  document.querySelectorAll('#adminSheet [data-k]').forEach((el) => {
    const [grp, k] = el.dataset.k.split('.');
    s[grp][k] = el.type === 'checkbox' ? el.checked : el.type === 'range' ? +el.value : el.value;
  });
  s.test_names = adminLists.test_names;
  s.field_test_names = adminLists.field_test_names;
  s.photo = { max_dim: +$('aMax').value, quality: +$('aQuality').value, review: $('aReview').checked, aspect: $('aPhotoAspect').value };
  s.video = { max_res: +$('aVideoRes').value, audio: $('aAudio').checked, aspect: $('aVideoAspect').value };
  $('adminSave').disabled = true;
  const r = await api('admin.php', { json: { action: 'settings_save', settings: s } });
  $('adminSave').disabled = false;
  if (!r.ok) { $('adminErr').textContent = r.error; return; }
  state.settings = r.settings; kvSet('settings', r.settings);
  toast('Saved — staff phones update when they next connect');
  closeSheet();
}
async function onLogoFile(e) {
  const file = e.target.files?.[0]; e.target.value = '';
  if (!file) return;
  try {
    const bmp = await toBitmap(file);
    const sc = Math.min(1, 800 / Math.max(bmp.width, bmp.height));
    const c = document.createElement('canvas');
    c.width = Math.round(bmp.width * sc); c.height = Math.round(bmp.height * sc);
    c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
    const png = await new Promise((res) => c.toBlob(res, 'image/png'));
    const fd = new FormData(); fd.append('action', 'logo_upload'); fd.append('logo', png, 'logo.png');
    const r = await api('admin.php', { body: fd });
    if (!r.ok) { toast(r.error, true); return; }
    state.settings.logo_version = r.settings.logo_version;
    await kvSet('logo', { version: r.settings.logo_version, data: await png.arrayBuffer() });
    state.logoVersion = 0; await loadLogo();
    renderLogoBox(); drawSamples(); toast('Logo uploaded');
  } catch (err) { toast('Could not read that image', true); }
}
async function removeLogo() {
  if (!confirm('Remove the company logo from field photos?')) return;
  const r = await api('admin.php', { json: { action: 'logo_delete' } });
  if (!r.ok) { toast(r.error, true); return; }
  state.settings.logo_version = 0; state.logo = null; state.logoVersion = 0;
  await kvDel('logo'); renderLogoBox();
}

/* ======================= status ======================= */
function renderNet() {
  const p = $('netPill');
  if (!navigator.onLine) { p.textContent = 'Offline'; p.className = 'pill warn'; }
  else if (state.syncing) { p.textContent = 'Uploading…'; p.className = 'pill ok'; }
  else { p.textContent = 'Online'; p.className = 'pill ok'; }
}

/* ======================= wiring ======================= */
function wire() {
  $('loginForm').addEventListener('submit', doLogin);
  $('nameForm').addEventListener('submit', savePhotographer);
  $('changeName').addEventListener('click', () => { closeSheetNow(); askPhotographer(); });
  $('jobSearch').addEventListener('input', renderJobs);
  $('jobList').addEventListener('click', onJobListClick);
  $('newJobBtn').addEventListener('click', () => { state.editingJob = null; openSheet('jobSheet'); });
  $('jobForm').addEventListener('submit', saveJob);
  $('jNo').addEventListener('input', updateFolderHint);
  $('jSite').addEventListener('input', updateFolderHint);
  $('jLoc').addEventListener('input', updateFolderHint);
  $('jobDelete').addEventListener('click', deleteJob);
  $('jobsQueueBtn').addEventListener('click', () => openSheet('queueSheet'));
  $('jobsSettingsBtn').addEventListener('click', () => openSheet('settingsSheet'));
  $('typeBack').addEventListener('click', goBack);
  document.querySelectorAll('.type-card').forEach((b) => b.addEventListener('click', () => pickType(b.dataset.type)));

  $('camBack').addEventListener('click', () => { if (state.rec) { toast('Stop the recording first'); return; } goBack(); });
  $('camErrBack').addEventListener('click', goBack);
  $('shutter').addEventListener('click', onShutter);
  $('ctxBtn').addEventListener('click', () => { if (!state.rec) openSheet('detailsSheet'); });
  $('gpsPill').addEventListener('click', showGpsInfo);
  $('editBtn').addEventListener('click', () => { if (state.rec) { toast('Stop the recording first'); return; } openSheet('detailsSheet'); });
  $('queueBtn').addEventListener('click', () => { if (!state.rec) openSheet('queueSheet'); });
  $('stampBtn').addEventListener('click', () => { if (!state.rec) openSheet('adminSheet'); });
  document.querySelectorAll('.mode-switch button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode)));
  $('scrim').addEventListener('click', closeSheet);
  document.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', closeSheet));
  $('detailsForm').addEventListener('submit', saveDetails);
  $('fTestSel').addEventListener('change', () => {
    $('fTestOtherRow').hidden = $('fTestSel').value !== '__other';
    if ($('fTestSel').value === '__other') $('fTest').focus();
  });
  $('syncNow').addEventListener('click', async () => {
    for (const r of await qAll()) if (r.status === 'error') { r.status = 'pending'; await qPut(r); }
    if (!navigator.onLine) toast('Phone is offline', true);
    syncQueue(); renderQueue();
  });
  $('queueList').addEventListener('click', onQueueClick);
  $('logoutBtn').addEventListener('click', logout);
  $('changeNasBtn').addEventListener('click', () => ANDROID_APP?.changeServer());
  $('themeSeg').addEventListener('click', (e) => { const b = e.target.closest('[data-theme]'); if (b) applyTheme(b.dataset.theme); });
  $('submitJobBtn').addEventListener('click', submitJob);
  // upload photos from the phone
  $('uploadPick').addEventListener('click', () => $('uploadInput').click());
  $('uploadInput').addEventListener('change', onUploadFiles);
  $('upType').addEventListener('click', (e) => { const b = e.target.closest('[data-type]'); if (!b) return; upload.type = b.dataset.type; renderUploadForm(true); });
  $('upCoordMode').addEventListener('click', (e) => { const b = e.target.closest('[data-mode]'); if (!b) return; upload.coordMode = b.dataset.mode; renderUploadForm(false); });
  $('upTestSel').addEventListener('change', () => renderUploadForm(false));
  ['upLat', 'upLon', 'upZone', 'upBand', 'upE', 'upN'].forEach((id) => $(id).addEventListener('input', () => renderUploadForm(false)));
  $('uploadForm').addEventListener('submit', submitUpload);
  $('jobTabs').addEventListener('click', (e) => {
    const b = e.target.closest('[data-tab]'); if (!b) return;
    state.jobTab = b.dataset.tab; renderJobs();
  });
  $('adminBtn').addEventListener('click', () => openSheet('adminSheet'));
  $('adminSave').addEventListener('click', saveAdmin);
  $('adminSheet').addEventListener('click', (e) => {
    const sw = e.target.closest('[data-swatch-k]'); if (!sw) return;
    const k = sw.dataset.swatchK;
    $('adminSheet').querySelector(`[data-k="${k}"]`).value = sw.dataset.c;
    $('adminSheet').querySelectorAll(`[data-swatch-k="${k}"]`).forEach((b) => b.classList.toggle('on', b === sw));
    drawSamples();
  });
  $('adminSheet').addEventListener('input', (e) => {
    if (e.target.type === 'range') e.target.nextElementSibling.textContent = e.target.value + '%';
    const k = e.target.dataset?.k || '';
    if (k.endsWith('.band')) $('adminSheet').querySelector(`[data-bg-for="${k.split('.')[0]}"]`).hidden = e.target.value === 'none';
    drawSamples();
  });
  $('adminSheet').addEventListener('change', drawSamples);
  $('adminSheet').addEventListener('click', onTestListClick);
  $('adminSheet').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.closest('.test-add input')) { e.preventDefault(); e.target.closest('.test-add').querySelector('.add-ok').click(); }
  });
  $('logoPick').addEventListener('click', () => $('logoInput').click());
  $('logoInput').addEventListener('change', onLogoFile);
  $('logoRemove').addEventListener('click', removeLogo);
  $('switchBtn').addEventListener('click', () => { if (state.rec) return; state.facing = state.facing === 'environment' ? 'user' : 'environment'; startCamera(); });
  $('torchBtn').addEventListener('click', async () => {
    try {
      state.torch = !state.torch;
      await state.track.applyConstraints({ advanced: [{ torch: state.torch }] });
      $('torchBtn').classList.toggle('on', state.torch);
    } catch { toast('Torch not supported'); }
  });
  $('retryCam').addEventListener('click', startCamera);
  $('retakeBtn').addEventListener('click', goBack);
  $('keepBtn').addEventListener('click', async () => {
    const p = state.pending; if (!p) return;
    $('keepBtn').disabled = true;
    try { await savePhoto(p.blob, p.meta); goBack(); }
    catch (e) { toast(e.message || 'Could not save', true); }
    finally { $('keepBtn').disabled = false; }
  });
  $('video').addEventListener('loadedmetadata', layoutPreview);
  $('video').addEventListener('resize', layoutPreview);
  window.addEventListener('resize', layoutPreview);

  window.addEventListener('online', () => { renderNet(); syncQueue(); if (state.auth) loadBootstrap(); });
  window.addEventListener('offline', renderNet);
  document.addEventListener('visibilitychange', () => {
    if (!state.auth) return;
    if (document.hidden) { if (state.rec) stopRecording(); stopCamera(); }
    else { if (state.screen === 'cam') startCamera(); syncQueue(); }
  });
  setInterval(() => syncQueue(), 20000);
  setInterval(() => { renderGps(); if (state.screen === 'cam' && !openSheetId) { drawPreview(); updateOrientation(); } }, 1000);
}

(async function boot() {
  wire();
  wirePinchZoom();
  blockPageZoom();
  applyTheme(currentTheme());
  enhanceAllSelects();
  // Sheets (admin settings, details) are re-drawn often: give new <select>s the custom drop-down too
  let ddQueued = false;                                  // at most once per screen frame (cheap)
  new MutationObserver(() => { if (ddQueued) return; ddQueued = true; requestAnimationFrame(() => { ddQueued = false; enhanceAllSelects(); }); }).observe(document.body, { childList: true, subtree: true });
  document.querySelectorAll('[data-store]').forEach((el) => { el.textContent = el.dataset.store === 'the' ? STORE_THE : STORE; });
  document.fonts?.load(`600 20px ${STAMP_FONT}`).then(() => { drawPreview(); }).catch(() => {});
  // Offline cache for the browser version; the installed app already carries its files
  if ('serviceWorker' in navigator && !IS_NATIVE) {
    const hadSw = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.register('sw.js').catch(() => {});
    // A new version was downloaded in the background: it is used from the next opening
    navigator.serviceWorker.addEventListener('controllerchange', () => { if (hadSw) toast('FieldCam was updated — close and reopen the app to use the new version', false, 6000); });
  }
  try {
    const keys = ['auth', 'jobs', 'settings', 'jobDetails', 'nasUrl', 'photographer'];
    const [auth, jobs, settings, jobDetails, savedNas, photographer] = await Promise.all(keys.map(kvGet));
    if (IS_NATIVE && savedNas) nasUrl = savedNas;
    if (photographer) state.photographer = photographer;
    if (jobs) state.jobs = jobs;
    if (settings) state.settings = settings;
    kvDel('prefs'); kvDel('override');   // old per-phone settings no longer used
    if (jobDetails) state.jobDetails = jobDetails;
    getKey();
    // A video that was interrupted (app closed while recording): keep what was saved
    for (const r of await qAll()) {
      if (!r.complete) {
        const n = await tx('chunks', 'readonly', (s) => s.count(IDBKeyRange.bound(r.uid + '#', r.uid + '#￿')));
        if (n) { r.total = n; r.complete = true; r.status = 'pending'; r.meta.interrupted = true; await qPut(r); }
        else await qRemove(r.uid);
      }
    }
    if (state.settings) loadLogo();
    if (auth?.token) { state.auth = auth; if (auth.shared && !state.photographer) askPhotographer(); else enterApp(); }
    else showLogin();
  } catch (e) {
    showLogin();
    $('loginErr').textContent = 'App storage unavailable: ' + e.message;
  }
})();
