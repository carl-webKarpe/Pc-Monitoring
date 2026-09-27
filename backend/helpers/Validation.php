<?php
declare(strict_types=1);

final class Validation
{
    public static function body(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') return [];
        $data = json_decode($raw, true);
        if (!is_array($data)) Response::error('Invalid JSON body', 'INVALID_JSON', 400);
        return $data;
    }

    public static function required(array $data, array $fields): void
    {
        $errors = [];
        foreach ($fields as $field) if (!isset($data[$field]) || trim((string)$data[$field]) === '') $errors[$field] = $field . ' is required';
        if ($errors !== []) Response::json(false, 'Validation failed', null, 422, $errors);
    }

    public static function login(array $data): void { self::required($data, ['username', 'password']); }
    public static function resource(array $data, string $resource): void
    {
        self::required($data, ['firstName', 'lastName', 'email', 'username', 'password']);
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) Response::json(false, 'Validation failed', null, 422, ['email' => 'Email is invalid']);
        if (!preg_match('/^[A-Za-z0-9._-]{3,40}$/', (string)$data['username'])) Response::json(false, 'Validation failed', null, 422, ['username' => 'Username must be 3-40 characters']);
        if ($resource === 'users' && isset($data['role']) && $data['role'] !== 'Tenant') Response::json(false, 'Validation failed', null, 422, ['role' => 'User role must be Tenant']);
        if ($resource === 'admins' && isset($data['role']) && $data['role'] !== 'Admin') Response::json(false, 'Validation failed', null, 422, ['role' => 'New administrators must use the Admin role']);
    }
    public static function id(string $id): int { if (!ctype_digit($id) || (int)$id < 1) Response::error('Invalid resource ID', 'INVALID_ID', 422); return (int)$id; }
}
