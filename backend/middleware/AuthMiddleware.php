<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Security.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

final class AuthMiddleware
{
    public const LOGIN_ROLES = ['Super Admin', 'Admin'];
    public const MAX_SESSION_SECONDS = 43200; // a session never lasts longer than 12 hours

    // Idle limit from the "Session Timeout" setting (5 minutes .. 24 hours, default 30 minutes).
    public static function idleSeconds(): int { return Security::durationSeconds(MySQLRepository::setting('sessionTimeout'), 1800, 300, 86400); }

    public static function startUserSession(array $user): void
    {
        mst_start_session();
        session_regenerate_id(true);
        $_SESSION = ['mst_user' => $user, 'mst_login_at' => time(), 'mst_last_activity' => time()];
        Security::csrfToken();
    }

    public static function requireAuth(): array
    {
        mst_start_session();
        if (empty($_SESSION['mst_user']['id'])) Response::error('Authentication required', 'UNAUTHENTICATED', 401);
        $now = time();
        if ($now - (int)($_SESSION['mst_last_activity'] ?? 0) > self::idleSeconds() || $now - (int)($_SESSION['mst_login_at'] ?? 0) > self::MAX_SESSION_SECONDS) {
            $userId = (int)$_SESSION['mst_user']['id'];
            self::endSession();
            MySQLRepository::log($userId, 'SESSION_EXPIRED', 'Signed out after inactivity', 'user', (string)$userId);
            Response::error('Your session expired. Please sign in again.', 'SESSION_EXPIRED', 401);
        }
        // Re-read the account on every request so deactivation or a role change takes effect immediately.
        $account = MySQLRepository::findAccount((int)$_SESSION['mst_user']['id']);
        if (!$account || $account['status'] !== 'Active' || !in_array($account['role'], self::LOGIN_ROLES, true)) {
            self::endSession();
            Response::error('Authentication required', 'UNAUTHENTICATED', 401);
        }
        if (Security::isStateChanging()) Security::requireCsrf();
        $_SESSION['mst_user'] = Security::publicUser($account);
        $_SESSION['mst_last_activity'] = $now;
        return $_SESSION['mst_user'];
    }

    public static function endSession(): void
    {
        mst_start_session();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) { $params = session_get_cookie_params(); setcookie(session_name(), '', ['expires' => time() - 42000, 'path' => $params['path'], 'domain' => $params['domain'], 'secure' => $params['secure'], 'httponly' => $params['httponly'], 'samesite' => $params['samesite'] ?: 'Strict']); }
        session_destroy();
    }
}
