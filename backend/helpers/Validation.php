<?php
declare(strict_types=1);

final class Validation
{
    public const ACCOUNT_STATUSES = ['Active', 'Inactive', 'Suspended'];

    public static function body(): array
    {
        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') return [];
        $data = json_decode($raw, true);
        if (!is_array($data)) Response::error('Invalid JSON body', 'INVALID_JSON', 400);
        return $data;
    }

    public static function fail(array $errors): never { Response::error('Validation failed', 'VALIDATION_FAILED', 422, $errors); }

    public static function required(array $data, array $fields): void
    {
        $errors = [];
        foreach ($fields as $field) if (!isset($data[$field]) || !is_scalar($data[$field]) || trim((string)$data[$field]) === '') $errors[$field] = $field . ' is required';
        if ($errors !== []) self::fail($errors);
    }

    public static function login(array $data): void { self::required($data, ['username', 'password']); }

    // Create requires every account field; update ($partial) validates only the fields that were sent.
    public static function resource(array $data, string $resource, bool $partial = false): void
    {
        if (!$partial) self::required($data, ['firstName', 'lastName', 'email', 'username', 'password']);
        $errors = [];
        foreach (['firstName', 'middleName', 'lastName', 'email', 'username', 'password', 'status', 'role'] as $field) if (array_key_exists($field, $data) && $data[$field] !== null && !is_scalar($data[$field])) $errors[$field] = $field . ' is invalid';
        if ($errors !== []) self::fail($errors);
        foreach (['firstName', 'lastName'] as $field) if (isset($data[$field]) && (trim((string)$data[$field]) === '' || mb_strlen(trim((string)$data[$field])) > 80)) $errors[$field] = $field . ' must be 1-80 characters';
        if (isset($data['middleName']) && mb_strlen(trim((string)$data['middleName'])) > 80) $errors['middleName'] = 'middleName must be at most 80 characters';
        if (isset($data['email']) && (!filter_var((string)$data['email'], FILTER_VALIDATE_EMAIL) || strlen((string)$data['email']) > 190)) $errors['email'] = 'Email is invalid';
        if (isset($data['username']) && !preg_match('/^[A-Za-z0-9._-]{3,40}$/', (string)$data['username'])) $errors['username'] = 'Username must be 3-40 characters';
        if (!$partial && strlen((string)$data['password']) < 8) $errors['password'] = 'Password must be at least 8 characters';
        if (isset($data['status']) && !in_array($data['status'], self::ACCOUNT_STATUSES, true)) $errors['status'] = 'Status must be Active, Inactive, or Suspended';
        if ($resource === 'users' && isset($data['role']) && $data['role'] !== 'Tenant') $errors['role'] = 'User role must be Tenant';
        if ($resource === 'admins' && isset($data['role']) && $data['role'] !== 'Admin') $errors['role'] = 'New administrators must use the Admin role';
        if ($errors !== []) self::fail($errors);
    }

    public static function id(string $id): int { if (!ctype_digit($id) || (int)$id < 1) Response::error('Invalid resource ID', 'INVALID_ID', 422); return (int)$id; }
}
