<?php
declare(strict_types=1);

// Website router for PHP's built-in server:  php -S localhost:8000 router.php
// Serves only the dashboard's own files (HTML, CSS, JS, images, fonts) from allowed folders, with security
// headers. Everything else (.env, .git, backend/, database/, agent/ with its device token, .venv/ ...) is a 404.

if (PHP_SAPI !== 'cli-server') { http_response_code(404); exit; }

const MST_TYPES = [
    'html' => 'text/html; charset=utf-8', 'css' => 'text/css; charset=utf-8', 'js' => 'text/javascript; charset=utf-8',
    'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'svg' => 'image/svg+xml',
    'ico' => 'image/x-icon', 'webp' => 'image/webp', 'woff' => 'font/woff', 'woff2' => 'font/woff2',
];
// Only HTML pages in the project root and management/, and assets/ for everything else.
const MST_ALLOWED = '#^/(?:[A-Za-z0-9_-]+\.html|management/[A-Za-z0-9_-]+\.html|assets/[A-Za-z0-9_./-]+)$#';

$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/');
if ($path === '/') $path = '/index.html';

$root = realpath(__DIR__);
$file = realpath(__DIR__ . $path);
$extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
// Pages may not be framed, may not load plugins, and forms/base URLs stay on this site.
header("Content-Security-Policy: frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'");

$allowed = preg_match(MST_ALLOWED, $path) && !str_contains($path, '..') && isset(MST_TYPES[$extension])
    && $file !== false && is_file($file) && str_starts_with($file, $root . DIRECTORY_SEPARATOR);
if (!$allowed) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Not found';
    return true;
}

header('Content-Type: ' . MST_TYPES[$extension]);
header('Cache-Control: ' . ($extension === 'html' ? 'no-cache' : 'public, max-age=300'));
header('Content-Length: ' . filesize($file));
readfile($file);
return true;
