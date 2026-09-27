<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

final class HealthController
{
    private const TABLES = ['users', 'computers', 'threats', 'scans', 'activity_logs', 'permissions', 'settings'];

    // Development-only: disabled when APP_ENV=production. Never returns credentials, DSNs, paths or stack traces.
    public static function database(string $method): never
    {
        if (mst_config()['app_env'] === 'production') Response::error('Endpoint not found', 'NOT_FOUND', 404);
        if ($method !== 'GET') Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        $database = mst_config()['db_name'];
        try { Database::connection(); }
        catch (Throwable $exception) { error_log('Database health check failed: ' . $exception->getMessage()); Response::error('Database connection failed', 'DATABASE_UNAVAILABLE', 500); }
        $tables = [];
        foreach (self::TABLES as $table) {
            try { $tables[$table] = MySQLRepository::tableAccessible($table); }
            catch (Throwable $exception) { error_log("Database health check failed for table $table: " . $exception->getMessage()); $tables[$table] = false; }
        }
        if (in_array(false, $tables, true)) Response::error('Database connected, but some tables are not accessible', 'DATABASE_TABLES_UNAVAILABLE', 500, ['database' => $database, 'tables' => $tables]);
        Response::success('Database connection successful', ['database' => $database, 'tables' => $tables]);
    }
}
