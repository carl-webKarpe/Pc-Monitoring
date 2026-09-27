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
    public static function login(array $data): never
    {
        Validation::login($data);
        // "username" may hold a username or an email address.
        $account = MySQLRepository::findForLogin(trim((string)$data['username']));
        $passwordValid = $account && Security::verify((string)$data['password'], (string)$account['passwordHash']);
        if ($passwordValid && $account['status'] === 'Active' && in_array($account['role'], AuthMiddleware::LOGIN_ROLES, true)) {
            mst_start_session();
            session_regenerate_id(true);
            MySQLRepository::touchLogin((int)$account['id']);
            $user = Security::publicUser($account);
            $_SESSION['mst_user'] = $user;
            MySQLRepository::log((int)$account['id'], 'LOGIN', 'Successful login', 'user', (string)$account['id']);
            Response::success('Login successful', ['user' => $user]);
        }
        // The typed identifier is not logged: users sometimes type a password into the username field.
        $reason = !$account ? 'unknown account' : (!$passwordValid ? 'invalid password' : ($account['status'] !== 'Active' ? 'inactive account' : 'role not permitted'));
        MySQLRepository::log($account ? (int)$account['id'] : null, 'LOGIN_FAILED', "Failed login attempt ($reason)", 'user', $account ? (string)$account['id'] : null);
        Response::error('Invalid username or password', 'INVALID_CREDENTIALS', 401);
    }

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
        Response::success('Authenticated user', ['user' => $user]);
    }
}
