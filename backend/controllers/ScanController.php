<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class ScanController
{
    public static function index(string $method, ?string $id = null): never
    {
        if ($method !== 'GET') Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        if ($id === null) ResourceController::list('scans');
        ResourceController::show('scans', $id);
    }
}
