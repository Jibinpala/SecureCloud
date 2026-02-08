const CACHE_NAME = 'kryox-v1';
const ASSETS = [
    '/',
    '/static/style.css',
    '/static/additional.css',
    '/static/professional.css',
    '/static/dashboard.css',
    '/static/professional.js',
    '/static/kxui.js',
    '/static/kryox_app_icon.png'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(ASSETS);
        })
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});
