<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class ReportController
{
    // /api/reports (Reports module) and /api/dashboard (Dashboard module) share the same database summary.
    public static function index(string $method, string $module = 'reports'): never
    {
        if ($method !== 'GET') Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        RoleMiddleware::allowModule($module);
        Response::success('Request successful', MySQLRepository::reports());
    }
}
