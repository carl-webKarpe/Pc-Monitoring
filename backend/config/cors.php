<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function mst_apply_cors(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    $allowed = mst_config()['frontend_origin'];
    if ($origin === $allowed) {
        header('Access-Control-Allow-Origin: ' . $allowed);
        header('Access-Control-Allow-Credentials: true');
    }
    header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Vary: Origin');
}
