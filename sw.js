// خدمة بسيطة: الشبكة أولًا، ومخزن احتياطي لواجهة التطبيق فقط (البيانات تأتي دائمًا من الإنترنت)
const CACHE = 'madakhil-shell-v1';
self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.method !== 'GET' || new URL(r.url).origin !== location.origin) return;
  e.respondWith(
    fetch(r).then(res => { const c = res.clone(); caches.open(CACHE).then(ch => ch.put(r, c)).catch(() => {}); return res; })
      .catch(() => caches.match(r).then(m => m || caches.match('./')))
  );
});
