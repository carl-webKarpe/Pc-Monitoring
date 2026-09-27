<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/AuthMiddleware.php';

final class RoleMiddleware
{
    public static function allow(array $roles): array
    {
        $user = AuthMiddleware::requireAuth();
        if (!in_array($user['role'], $roles, true)) Response::error('Forbidden', 'FORBIDDEN', 403);
        return $user;
    }
}
