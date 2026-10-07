/* FieldCam service worker: keeps a copy of the app on the phone.
   The app opens instantly from that copy (no waiting for the network), and the newest version is
   fetched in the background — it is used the next time FieldCam is opened.
   Photos and uploads never pass through this cache; the Android APK is always fetched fresh. */
const CACHE = 'fieldcam-v4.3.3';
const SHELL = ['./', 'index.html', 'styles.css', 'config.js', 'app.js', 'manifest.webmanifest',
  'fonts/RobotoCondensed.ttf', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/apple-touch-icon.png'];

self.addEventListener('install', (e) => {
  // 'reload' = straight from the website, never an older copy from the browser's own cache
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL.map((u) => new Request(u, { cache: 'reload' })))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== location.origin || url.pathname.includes('/api/') || url.pathname.includes('/android/')) return;
  e.respondWith(caches.open(CACHE).then(async (cache) => {
    const hit = await cache.match(req, { ignoreSearch: true });
    const fresh = fetch(req, { cache: 'no-cache' })
      .then((res) => { if (res.ok) cache.put(req, res.clone()); return res; })
      .catch(() => null);
    if (hit) { e.waitUntil(fresh); return hit; }          // instant: saved copy now, newest copy for next time
    const res = await fresh;
    if (res) return res;
    if (req.mode === 'navigate') return (await cache.match('index.html')) || Response.error();
    return Response.error();
  }));
});
