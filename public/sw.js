/*
 * Minimal, safe service worker:
 *  - navigations: network-first, falling back to the cached page, then the home page
 *  - everything else same-origin GETs: cache-first, with network backfill
 */
const CACHE = 'pjblanco-v1';
const CORE = [
	'/',
	'/index.html',
	'/manifest.webmanifest',
	'/icons/icon-192.png',
	'/icons/icon-512.png',
	'/favicon.svg',
];

self.addEventListener('install', (event) => {
	event.waitUntil(
		caches
			.open(CACHE)
			.then((cache) => cache.addAll(CORE))
			.then(() => self.skipWaiting()),
	);
});

self.addEventListener('activate', (event) => {
	event.waitUntil(
		caches
			.keys()
			.then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
			.then(() => self.clients.claim()),
	);
});

self.addEventListener('fetch', (event) => {
	const request = event.request;
	if (request.method !== 'GET' || !request.url.startsWith(self.location.origin)) return;

	if (request.mode === 'navigate') {
		event.respondWith(
			fetch(request)
				.then((response) => {
					const copy = response.clone();
					caches.open(CACHE).then((cache) => cache.put(request, copy));
					return response;
				})
				.catch(() =>
					caches.match(request).then((cached) => cached || caches.match('/index.html')),
				),
		);
		return;
	}

	event.respondWith(
		caches.match(request).then(
			(cached) =>
				cached ||
				fetch(request).then((response) => {
					if (response.ok || response.type === 'opaque') {
						const copy = response.clone();
						caches.open(CACHE).then((cache) => cache.put(request, copy));
					}
					return response;
				}),
		),
	);
});
