/* Service Worker «Meine Meerschweinchen»
   - App-Dateien: zuerst Netzwerk (immer aktuell), offline aus dem Zwischenspeicher.
   - Bibliotheken und Schriften von CDNs: aus dem Zwischenspeicher, im Hintergrund aktualisiert.
   - Microsoft (Anmeldung, OneDrive) und Wetterdienst: nie zwischengespeichert. */
const VERSION = 'mm-2026-11-02-1';
const SHELL = ['./', './index.html', './cloud.js', './config.js', './manifest.webmanifest', './anleitung.html',
  './icons/icon-192.png', './icons/icon-512.png', './icons/apple-touch-icon.png', './icons/favicon-32.png'];
const CDN = ['cdnjs.cloudflare.com', 'fonts.googleapis.com', 'fonts.gstatic.com'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

const timeout = (ms) => new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms));

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin === location.origin) {
    e.respondWith((async () => {
      const cache = await caches.open(VERSION);
      try {
        const res = await Promise.race([fetch(req), timeout(5000)]);
        if (res && res.ok && res.type === 'basic') cache.put(req.mode === 'navigate' ? './index.html' : req, res.clone());
        return res;
      } catch {
        const hit = await cache.match(req.mode === 'navigate' ? './index.html' : req, { ignoreSearch: true });
        return hit || new Response('Offline – diese Datei ist noch nicht zwischengespeichert.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }
    })());
    return;
  }
  if (CDN.includes(url.hostname)) {
    e.respondWith((async () => {
      const cache = await caches.open(VERSION);
      const hit = await cache.match(req);
      const net = fetch(req).then((res) => { if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone()); return res; }).catch(() => null);
      return hit || (await net) || new Response('', { status: 504 });
    })());
  }
  // alles andere (login.microsoftonline.com, graph.microsoft.com, *.sharepoint.com, open-meteo) direkt ins Netz
});
