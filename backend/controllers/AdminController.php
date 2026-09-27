<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class AdminController
{
    public static function index(string $method, ?string $id = null): never
    {
        if ($method === 'GET' && $id === null) ResourceController::list('admins');
        if ($method === 'GET') ResourceController::show('admins', $id);
        if ($method === 'POST' && $id === null) ResourceController::create('admins');
        if ($method === 'PUT' && $id !== null) ResourceController::update('admins', $id);
        if ($method === 'DELETE' && $id !== null) ResourceController::delete('admins', $id);
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }
}
