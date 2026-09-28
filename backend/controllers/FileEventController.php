<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

// File activity reported by the lab-PC agents (read-only for the dashboard in Phase 9).
final class FileEventController
{
    public static function index(string $method, ?string $id = null): never
    {
        if ($method !== 'GET' || $id !== null) Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        RoleMiddleware::allowModule('computer_monitoring');
        $filters = Validation::filters(['computerId' => ['computer_id', 'id'], 'type' => ['event_type', ['created', 'deleted']], 'status' => ['status', ['New', 'Reviewed', 'Scan Requested', 'Scanned']]]);
        [$limit, $offset] = Validation::page(100, 500);
        Response::success('Request successful', MySQLRepository::list('file_events', $filters, $limit, $offset));
    }
}
