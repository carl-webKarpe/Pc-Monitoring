<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Security.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

final class AuthMiddleware
{
    public const LOGIN_ROLES = ['Super Admin', 'Admin'];

    public static function requireAuth(): array
    {
        mst_start_session();
        if (empty($_SESSION['mst_user']['id'])) Response::error('Authentication required', 'UNAUTHENTICATED', 401);
        // Re-read the account on every request so deactivation or a role change takes effect immediately.
        $account = MySQLRepository::findAccount((int)$_SESSION['mst_user']['id']);
        if (!$account || $account['status'] !== 'Active' || !in_array($account['role'], self::LOGIN_ROLES, true)) {
            self::endSession();
            Response::error('Authentication required', 'UNAUTHENTICATED', 401);
        }
        $_SESSION['mst_user'] = Security::publicUser($account);
        return $_SESSION['mst_user'];
    }

    public static function endSession(): void
    {
        mst_start_session();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) { $params = session_get_cookie_params(); setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']); }
        session_destroy();
    }
}
