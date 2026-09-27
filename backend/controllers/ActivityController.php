<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class ActivityController
{
    public static function index(string $method): never
    {
        if ($method !== 'GET') Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        RoleMiddleware::allowModule('activity_logs');
        [$limit, $offset] = Validation::page(100, 500);
        Response::success('Request successful', MySQLRepository::activity($limit, $offset));
    }
}
