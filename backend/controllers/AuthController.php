<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php'; require_once __DIR__ . '/../helpers/Response.php'; require_once __DIR__ . '/../helpers/Validation.php'; require_once __DIR__ . '/../helpers/Security.php'; require_once __DIR__ . '/../middleware/AuthMiddleware.php'; require_once __DIR__ . '/../repositories/MySQLRepository.php';
final class AuthController {
    public static function login(array $data): never { Validation::login($data); $account = MySQLRepository::findByUsername(trim((string)$data['username'])); if ($account && Security::verify((string)$data['password'], (string)$account['passwordHash']) && $account['status'] === 'Active' && in_array($account['role'], ['Super Admin', 'Admin'], true)) { mst_start_session(); session_regenerate_id(true); MySQLRepository::touchLogin((int)$account['id']); $user = Security::publicUser($account); unset($user['passwordHash']); $_SESSION['mst_user'] = $user; MySQLRepository::log((int)$account['id'], 'LOGIN', 'Successful login'); Response::success('Login successful', ['user' => $user]); } Response::error('Invalid username or password', 'INVALID_CREDENTIALS', 401); }
    public static function logout(): never { mst_start_session(); $_SESSION = []; if (ini_get('session.use_cookies')) { $params = session_get_cookie_params(); setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']); } session_destroy(); Response::success('Logout successful', null); }
    public static function me(): never { $user = AuthMiddleware::requireAuth(); Response::success('Authenticated user', ['user' => Security::publicUser($user)]); }
}
