<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validation.php';
require_once __DIR__ . '/../helpers/Security.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

final class AuthController
{
    public const LOCKOUT_MINUTES = 15;

    public static function login(array $data): never
    {
        Validation::login($data);
        // "username" may hold a username or an email address.
        $account = MySQLRepository::findForLogin(trim((string)$data['username']));
        $accountId = $account ? (int)$account['id'] : null;
        $ip = Security::clientIp();

        // Lockout: too many recent failures for this account (since its last good login) or from this IP address.
        $limit = Security::attemptLimit(MySQLRepository::setting('loginLimit'));
        [$accountFailures, $ipFailures] = MySQLRepository::recentLoginFailures($accountId, $ip, self::LOCKOUT_MINUTES);
        if ($accountFailures >= $limit || $ipFailures >= $limit * 3) {
            MySQLRepository::log($accountId, 'LOGIN_LOCKED', 'Login blocked: too many failed attempts', 'user', $accountId !== null ? (string)$accountId : null);
            header('Retry-After: ' . (self::LOCKOUT_MINUTES * 60));
            Response::error('Too many failed login attempts. Try again in ' . self::LOCKOUT_MINUTES . ' minutes.', 'LOGIN_LOCKED', 429);
        }

        if ($account) $passwordValid = Security::verify((string)$data['password'], (string)$account['passwordHash']);
        else { Security::verifyAgainstDummy((string)$data['password']); $passwordValid = false; }

        if ($passwordValid && $account['status'] === 'Active' && in_array($account['role'], AuthMiddleware::LOGIN_ROLES, true)) {
            $user = Security::publicUser($account);
            AuthMiddleware::startUserSession($user);
            MySQLRepository::touchLogin((int)$account['id']);
            MySQLRepository::log((int)$account['id'], 'LOGIN', 'Successful login', 'user', (string)$account['id']);
            Response::success('Login successful', ['user' => $user, 'csrfToken' => Security::csrfToken()]);
        }
        // The typed identifier is not logged: users sometimes type a password into the username field.
        $reason = !$account ? 'unknown account' : (!$passwordValid ? 'invalid password' : ($account['status'] !== 'Active' ? 'inactive account' : 'role not permitted'));
        MySQLRepository::log($accountId, 'LOGIN_FAILED', "Failed login attempt ($reason)", 'user', $accountId !== null ? (string)$accountId : null);
        Response::error('Invalid username or password', 'INVALID_CREDENTIALS', 401);
    }

    // Logout needs no CSRF token: the worst a forged logout can do is sign the user out.
    public static function logout(): never
    {
        mst_start_session();
        $userId = isset($_SESSION['mst_user']['id']) ? (int)$_SESSION['mst_user']['id'] : null;
        if ($userId !== null) MySQLRepository::log($userId, 'LOGOUT', 'Logged out', 'user', (string)$userId);
        AuthMiddleware::endSession();
        Response::success('Logout successful', null);
    }

    public static function me(): never
    {
        $user = AuthMiddleware::requireAuth();
        Response::success('Authenticated user', ['user' => $user, 'csrfToken' => Security::csrfToken(), 'sessionTimeoutSeconds' => AuthMiddleware::idleSeconds()]);
    }
}
