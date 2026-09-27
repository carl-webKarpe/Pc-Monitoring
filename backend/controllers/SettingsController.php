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
            $result = MySQLRepository::saveSettings($settings);
            MySQLRepository::log((int)$user['id'], 'SETTINGS_UPDATED', 'Updated settings: ' . implode(', ', array_keys($settings)), 'settings', null);
            Response::success('Settings updated', $result);
        }
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }
}
