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

    // Pages that update themselves -> the module that may read them and the data they show.
    private const LIVE_SCOPES = [
        'dashboard' => ['dashboard', ['computers', 'threats', 'scans', 'files', 'quarantine']],
        'reports' => ['reports', ['computers', 'threats', 'scans', 'files', 'quarantine']],
        'computers' => ['computer_monitoring', ['computers', 'files', 'quarantine']],
        'threats' => ['threats', ['threats', 'computers', 'activity']],
        'files' => ['computer_monitoring', ['files', 'computers', 'scans', 'quarantine', 'activity']],
        'downloads' => ['computer_monitoring', ['files', 'computers', 'scans', 'quarantine', 'activity']],
        'activity' => ['activity_logs', ['activity']],
    ];

    // /api/changes?scope=files: a tiny fingerprint of what that page shows. The page asks every second and reloads its
    // data only when the fingerprint changed (a heartbeat, a new file event, scan, threat, quarantine or log entry).
    public static function changes(string $method): never
    {
        if ($method !== 'GET') Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        $scope = (string)($_GET['scope'] ?? '');
        if (!isset(self::LIVE_SCOPES[$scope])) Validation::fail(['scope' => 'Unknown page']);
        [$module, $parts] = self::LIVE_SCOPES[$scope];
        RoleMiddleware::allowModule($module);
        Response::success('Request successful', ['version' => MySQLRepository::liveVersion($parts)]);
    }
}
