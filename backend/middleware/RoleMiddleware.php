<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';
require_once __DIR__ . '/AuthMiddleware.php';

final class RoleMiddleware
{
    // Authoritative MST role policy. The permissions table can only narrow it, never widen it.
    public const POLICY = [
        'Super Admin' => ['dashboard', 'computer_monitoring', 'network', 'threats', 'scan_history', 'reports', 'activity_logs', 'user_management', 'admin_management', 'permissions', 'settings'],
        'Admin' => ['dashboard', 'computer_monitoring', 'network', 'threats', 'file_scanner', 'scan_history', 'reports', 'activity_logs', 'settings'],
    ];
    public const MODULES = ['dashboard', 'computer_monitoring', 'network', 'threats', 'file_scanner', 'scan_history', 'reports', 'activity_logs', 'user_management', 'admin_management', 'permissions', 'settings'];

    public static function policyAllows(string $role, string $module): bool { return in_array($module, self::POLICY[$role] ?? [], true); }

    public static function allowModule(string $module): array
    {
        $user = AuthMiddleware::requireAuth();
        // A missing permissions row falls back to the policy; a row set to 0 revokes the module.
        if (!self::policyAllows($user['role'], $module) || MySQLRepository::permissionFor($user['role'], $module) === false) Response::error('Forbidden', 'FORBIDDEN', 403);
        return $user;
    }
}
