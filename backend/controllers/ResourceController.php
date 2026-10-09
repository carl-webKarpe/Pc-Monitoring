<?php
declare(strict_types=1);

require_once __DIR__ . '/../repositories/MySQLRepository.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validation.php';
require_once __DIR__ . '/../middleware/RoleMiddleware.php';

final class ResourceController
{
    public const MODULES = ['users' => 'user_management', 'admins' => 'admin_management', 'computers' => 'computer_monitoring', 'threats' => 'threats', 'scans' => 'scan_history'];
    public const THREAT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'];
    public const THREAT_STATUSES = ['Detected', 'Investigating', 'Quarantined', 'Resolved', 'Ignored'];
    public const SCAN_STATUSES = ['PENDING', 'SAFE', 'THREAT', 'WARNING', 'FAILED'];
    public const SCAN_TYPES = ['File Scan', 'Quick Scan', 'Security Scan', 'Network Scan'];
    private const ACCOUNT_LABELS = ['users' => ['USER', 'user'], 'admins' => ['ADMIN', 'admin']];

    private static function filters(string $resource): array
    {
        return match ($resource) {
            'threats' => ['severity' => ['severity', self::THREAT_SEVERITIES], 'status' => ['status', self::THREAT_STATUSES], 'computerId' => ['computer_id', 'id']],
            'scans' => ['status' => ['status', self::SCAN_STATUSES], 'type' => ['scan_type', self::SCAN_TYPES], 'computerId' => ['computer_id', 'id']],
            default => [],
        };
    }

    public static function list(string $resource): never
    {
        RoleMiddleware::allowModule(self::MODULES[$resource]);
        $filters = Validation::filters(self::filters($resource));
        [$limit, $offset] = Validation::page();
        Response::success('Request successful', MySQLRepository::list($resource, $filters, $limit, $offset));
    }

    public static function show(string $resource, string $id): never
    {
        RoleMiddleware::allowModule(self::MODULES[$resource]);
        $item = MySQLRepository::find($resource, Validation::id($id));
        if (!$item) Response::error('Resource not found', 'NOT_FOUND', 404);
        Response::success('Request successful', $item);
    }

    public static function create(string $resource): never
    {
        $user = RoleMiddleware::allowModule(self::MODULES[$resource]);
        $data = Validation::body();
        Validation::resource($data, $resource, false, self::strongPasswords());
        $item = self::guardDuplicates(fn() => MySQLRepository::create($resource, $data));
        [$action, $type] = self::ACCOUNT_LABELS[$resource];
        MySQLRepository::log((int)$user['id'], $action . '_CREATED', "Created $type {$item['username']}", $type, (string)$item['id']);
        Response::success('Resource saved', $item, 201);
    }

    public static function update(string $resource, string $id): never
    {
        $user = RoleMiddleware::allowModule(self::MODULES[$resource]);
        $validatedId = Validation::id($id);
        $existing = MySQLRepository::find($resource, $validatedId);
        if (!$existing) Response::error('Resource not found', 'NOT_FOUND', 404);
        $data = Validation::body();
        // The password rule also checks the username, so use the account's current one when it is not being changed.
        Validation::resource($data + ['username' => $existing['username']], $resource, true, self::strongPasswords());
        if (isset($data['status']) && $data['status'] !== 'Active' && ($validatedId === 1 || $validatedId === (int)$user['id'])) Response::error('This account cannot be deactivated', 'ACCOUNT_PROTECTED', 403);
        $item = self::guardDuplicates(fn() => MySQLRepository::update($resource, $validatedId, $data));
        // Only field names are logged, never values (so passwords never reach the audit log).
        $changed = array_values(array_filter(['firstName', 'middleName', 'lastName', 'email', 'username', 'status', 'password'], fn($field) => isset($data[$field]) && $data[$field] !== ''));
        [$action, $type] = self::ACCOUNT_LABELS[$resource];
        MySQLRepository::log((int)$user['id'], $action . '_UPDATED', "Updated $type {$item['username']}" . ($changed ? ': ' . implode(', ', $changed) : ''), $type, (string)$validatedId);
        Response::success('Resource updated', $item);
    }

    public static function delete(string $resource, string $id): never
    {
        $user = RoleMiddleware::allowModule(self::MODULES[$resource]);
        $validatedId = Validation::id($id);
        $item = MySQLRepository::find($resource, $validatedId);
        if (!$item) Response::error('Resource not found', 'NOT_FOUND', 404);
        if ($validatedId === 1 || $validatedId === (int)$user['id']) Response::error('This account cannot be removed', 'ACCOUNT_PROTECTED', 403);
        if (!MySQLRepository::delete($resource, $validatedId)) Response::error('Super Admin accounts cannot be removed', 'ACCOUNT_PROTECTED', 403);
        [$action, $type] = self::ACCOUNT_LABELS[$resource];
        MySQLRepository::log((int)$user['id'], $action . '_DELETED', "Deleted $type {$item['username']}", $type, (string)$validatedId);
        Response::success('Resource deleted', null);
    }

    // "Require Strong Password" setting: on unless explicitly turned off.
    private static function strongPasswords(): bool { return MySQLRepository::setting('strongPassword') !== '0'; }

    private static function guardDuplicates(callable $write): array
    {
        try { return $write(); }
        catch (PDOException $exception) { if ($exception->getCode() === '23000') Response::error('Email or username is already in use', 'DUPLICATE_ACCOUNT', 409); throw $exception; }
    }
}
