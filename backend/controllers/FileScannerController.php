<?php
declare(strict_types=1);

require_once __DIR__ . '/../middleware/RoleMiddleware.php';

final class FileScannerController
{
    public static function index(string $method): never
    {
        if ($method !== 'POST') Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        RoleMiddleware::allowModule('file_scanner');
        Response::error('The file scanner API is not implemented yet; the File Scanner page is a demo', 'NOT_IMPLEMENTED', 501);
    }
}
