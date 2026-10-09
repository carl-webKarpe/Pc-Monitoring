<?php
declare(strict_types=1);

require_once __DIR__ . '/Response.php';

final class Security
{
    public const CSRF_HEADER = 'HTTP_X_CSRF_TOKEN';

    public static function publicUser(array $user): array { unset($user['password'], $user['passwordHash']); return $user; }
    public static function hash(string $password): string { return password_hash($password, PASSWORD_DEFAULT); }
    public static function verify(string $password, string $hash): bool { return password_verify($password, $hash); }

    // Same cost (10, PHP 8.3 default and the seeded accounts) as a real check, so response time does not reveal whether a username exists.
    public static function verifyAgainstDummy(string $password): void { password_verify($password, '$2y$10$6WE8BzZIxx0AceLK6RQCueysYdhtuU6h8cODKIXN00.0SESIAsySq'); }

    /** "30 minutes" / "10 seconds" / "2 hours" -> seconds, clamped to [$min, $max]; $default when unreadable. */
    public static function durationSeconds(?string $value, int $default, int $min, int $max): int
    {
        if ($value === null || !preg_match('/^(\d{1,4}) (second|minute|hour)s?$/i', trim($value), $match)) return $default;
        return max($min, min($max, (int)$match[1] * ['second' => 1, 'minute' => 60, 'hour' => 3600][strtolower($match[2])]));
    }

    /** "5 attempts" -> 5, clamped to [3, 20]. */
    public static function attemptLimit(?string $value, int $default = 5): int
    {
        return $value !== null && preg_match('/^(\d{1,3}) attempts?$/i', trim($value), $match) ? max(3, min(20, (int)$match[1])) : $default;
    }

    /** Returns why a password is not acceptable, or null. The strong rule follows the "Require Strong Password" setting. */
    public static function passwordProblem(string $password, string $username, bool $strong): ?string
    {
        if (strlen($password) < 8) return 'Password must be at least 8 characters';
        if (strlen($password) > 72) return 'Password must be at most 72 characters';
        if (!$strong) return null;
        if (!preg_match('/[a-z]/', $password) || !preg_match('/[A-Z]/', $password) || !preg_match('/\d/', $password) || !preg_match('/[^A-Za-z0-9]/', $password)) return 'Password must include upper- and lowercase letters, a number and a symbol';
        if ($username !== '' && stripos($password, $username) !== false) return 'Password must not contain the username';
        return null;
    }

    // ---- CSRF: every state-changing request from a browser session must send the session's token ----

    public static function csrfToken(): string
    {
        if (empty($_SESSION['mst_csrf'])) $_SESSION['mst_csrf'] = bin2hex(random_bytes(32));
        return $_SESSION['mst_csrf'];
    }

    public static function requireCsrf(): void
    {
        $sent = (string)($_SERVER[self::CSRF_HEADER] ?? '');
        if ($sent === '' || empty($_SESSION['mst_csrf']) || !hash_equals($_SESSION['mst_csrf'], $sent)) {
            Response::error('Security token missing or invalid. Reload the page and try again.', 'CSRF_INVALID', 403);
        }
    }

    public static function isStateChanging(): bool { return !in_array(strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET'), ['GET', 'HEAD', 'OPTIONS'], true); }

    public static function clientIp(): ?string { $ip = (string)($_SERVER['REMOTE_ADDR'] ?? ''); return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null; }
}
