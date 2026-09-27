<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../helpers/Response.php';

final class AuthMiddleware
{
    public static function requireAuth(): array
    {
        mst_start_session();
        if (empty($_SESSION['mst_user'])) Response::error('Authentication required', 'UNAUTHENTICATED', 401);
        return $_SESSION['mst_user'];
    }
}
