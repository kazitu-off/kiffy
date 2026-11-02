/* Kiffy Service Worker v2.2.0 */
const CACHE_NAME = "kiffy-mobile-v2.2.0";
const PRECACHE = [
  "./",
  "./app.html",
  "./index.html",
  "./android.html",
  "./manifest.json",
  "./version.json"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  // Do not intercept WebSocket or POST requests or dynamic API
  if (event.request.method !== "GET" || url.pathname.endsWith("/ws") || url.pathname.includes("api.php")) {
    return;
  }
  event.respondWith(
    caches.match(event.request).then(cached => {
      const netFetch = fetch(event.request).then(networkResponse => {
        if (networkResponse && networkResponse.status === 200 && networkResponse.type === "basic") {
          const toCache = networkResponse.clone();
          caches.open(CACHE_NAME).then(c => c.put(event.request, toCache));
        }
        return networkResponse;
      }).catch(() => cached);
      return cached || netFetch;
    })
  );
});

self.addEventListener("message", event => {
  if (event.data === "skipWaiting") {
    self.skipWaiting();
  }
});
