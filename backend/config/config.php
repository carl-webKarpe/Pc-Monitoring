<?php
declare(strict_types=1);

const MST_DEMO_ACCOUNTS = [
    'superadmin' => ['id' => 1, 'username' => 'superadmin', 'name' => 'System Administrator', 'role' => 'Super Admin'],
    'admin' => ['id' => 2, 'username' => 'admin', 'name' => 'Administrator', 'role' => 'Admin'],
];

function mst_env(): array
{
    static $values;
    if ($values !== null) return $values;
    $values = [];
    $file = dirname(__DIR__, 2) . '/.env';
    if (is_readable($file)) foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) { if (str_starts_with(trim($line), '#') || !str_contains($line, '=')) continue; [$key, $value] = explode('=', $line, 2); $value = trim($value); if (strlen($value) >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[-1] === $value[0]) $value = substr($value, 1, -1); $values[trim($key)] = $value; }
    return $values;
}

function mst_config(): array
{
    return [
        'app_env' => strtolower(getenv('APP_ENV') ?: (mst_env()['APP_ENV'] ?? 'development')),
        // Comma-separated list, e.g. http://localhost:8000,http://127.0.0.1:8000
        'frontend_origins' => array_values(array_filter(array_map('trim', explode(',', getenv('FRONTEND_ORIGIN') ?: (mst_env()['FRONTEND_ORIGIN'] ?? 'http://localhost:8000'))))),
        'db_host' => getenv('DB_HOST') ?: (mst_env()['DB_HOST'] ?? '127.0.0.1'),
        'db_port' => getenv('DB_PORT') ?: (mst_env()['DB_PORT'] ?? '3306'),
        'db_name' => getenv('DB_DATABASE') ?: (mst_env()['DB_DATABASE'] ?? getenv('DB_NAME') ?: (mst_env()['DB_NAME'] ?? 'mst_database')),
        'db_user' => getenv('DB_USERNAME') ?: (mst_env()['DB_USERNAME'] ?? getenv('DB_USER') ?: (mst_env()['DB_USER'] ?? 'root')),
        'db_password' => getenv('DB_PASSWORD') !== false ? getenv('DB_PASSWORD') : (mst_env()['DB_PASSWORD'] ?? ''),
        'session_name' => 'mst_session',
        // Optional VirusTotal hash lookup (Phase 11). Only SHA-256 hashes are sent, never files.
        'virustotal_api_key' => trim((string)(getenv('VIRUSTOTAL_API_KEY') ?: (mst_env()['VIRUSTOTAL_API_KEY'] ?? ''))),
        'virustotal_api_url' => rtrim((string)(getenv('VIRUSTOTAL_API_URL') ?: (mst_env()['VIRUSTOTAL_API_URL'] ?? 'https://www.virustotal.com/api/v3')), '/'),
        'virustotal_ca_bundle' => (string)(getenv('VIRUSTOTAL_CA_BUNDLE') ?: (mst_env()['VIRUSTOTAL_CA_BUNDLE'] ?? '')),
    ];
}

function mst_is_https(): bool { return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https' && in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)); }

function mst_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $config = mst_config();
    session_name($config['session_name']);
    // Strict: the session cookie is never sent with requests started by other websites (CSRF defence in depth).
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict', 'secure' => mst_is_https()]);
    session_start();
}
