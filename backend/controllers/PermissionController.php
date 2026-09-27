<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class PermissionController
{
    public static function index(string $method, ?string $role = null): never
    {
        if ($method === 'GET' && $role === null) { RoleMiddleware::allowModule('permissions'); Response::success('Request successful', MySQLRepository::permissions()); }
        if ($method === 'PUT' && $role !== null) self::update($role);
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    private static function update(string $role): never
    {
        $user = RoleMiddleware::allowModule('permissions');
        $data = Validation::body();
        if (!isset(RoleMiddleware::POLICY[$role]) || !isset($data['permissions']) || !is_array($data['permissions']) || $data['permissions'] === []) Response::error('Invalid permission payload', 'INVALID_PERMISSIONS', 422);
        $errors = [];
        foreach ($data['permissions'] as $module => $allowed) {
            if (!in_array($module, RoleMiddleware::MODULES, true)) { $errors[$module] = 'Unknown module'; continue; }
            if (!is_bool($allowed)) { $errors[$module] = 'Must be true or false'; continue; }
            // The fixed MST role policy cannot be widened from the database.
            if ($allowed && !RoleMiddleware::policyAllows($role, $module)) $errors[$module] = "$role cannot be granted this module";
            if (!$allowed && $role === 'Super Admin' && $module === 'permissions') $errors[$module] = 'Super Admin must keep access to Permissions';
        }
        if ($errors !== []) Validation::fail($errors);
        $result = MySQLRepository::savePermissions($role, $data['permissions']);
        $summary = implode(', ', array_map(fn($module, $allowed) => $module . '=' . ($allowed ? 'allowed' : 'restricted'), array_keys($data['permissions']), $data['permissions']));
        MySQLRepository::log((int)$user['id'], 'PERMISSIONS_UPDATED', "Updated $role permissions: $summary", 'role', $role);
        Response::success('Permissions updated', $result);
    }
}
