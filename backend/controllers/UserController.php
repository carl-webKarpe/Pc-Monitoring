<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class UserController
{
    public static function index(string $method, ?string $id = null): never
    {
        if ($method === 'GET' && $id === null) ResourceController::list('users');
        if ($method === 'GET') ResourceController::show('users', $id);
        if ($method === 'POST' && $id === null) ResourceController::create('users');
        if ($method === 'PUT' && $id !== null) ResourceController::update('users', $id);
        if ($method === 'DELETE' && $id !== null) ResourceController::delete('users', $id);
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }
}
