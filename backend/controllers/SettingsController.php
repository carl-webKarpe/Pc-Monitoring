<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class SettingsController
{
    public static function index(string $method): never
    {
        $user = RoleMiddleware::allowModule('settings');
        if ($method === 'GET') Response::success('Request successful', MySQLRepository::settings());
        if ($method === 'PUT') {
            $settings = Validation::settings(Validation::body());
            // Scanner settings control file scanning, which only Admin accounts may do (MST role rules).
            $scannerKeys = array_keys(array_filter($settings, fn($setting) => $setting[0] === 'scanner'));
            if ($scannerKeys !== [] && !RoleMiddleware::policyAllows($user['role'], 'file_scanner')) {
                MySQLRepository::log((int)$user['id'], 'ACCESS_DENIED', "{$user['role']} tried to change scanner settings (" . implode(', ', $scannerKeys) . ')', 'module', 'file_scanner');
                Response::error('Only Admin accounts can change scanner settings', 'FORBIDDEN', 403);
            }
            $result = MySQLRepository::saveSettings($settings);
            MySQLRepository::log((int)$user['id'], 'SETTINGS_UPDATED', 'Updated settings: ' . implode(', ', array_keys($settings)), 'settings', null);
            Response::success('Settings updated', $result);
        }
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }
}
