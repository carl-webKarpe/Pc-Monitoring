<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

final class ThreatController
{
    public static function index(string $method, ?string $id = null, ?string $action = null): never
    {
        if ($method === 'GET' && $id === null) ResourceController::list('threats');
        if ($method === 'GET' && $action === null) ResourceController::show('threats', $id);
        if ($method === 'PUT' && $id !== null && $action === 'status') self::updateStatus($id);
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    private static function updateStatus(string $id): never
    {
        $user = RoleMiddleware::allowModule('threats');
        $threatId = Validation::id($id);
        $data = Validation::body();
        Validation::required($data, ['status']);
        if (!in_array($data['status'], ResourceController::THREAT_STATUSES, true)) Validation::fail(['status' => 'Status must be one of: ' . implode(', ', ResourceController::THREAT_STATUSES)]);
        $threat = MySQLRepository::find('threats', $threatId);
        if (!$threat) Response::error('Resource not found', 'NOT_FOUND', 404);
        $updated = MySQLRepository::updateThreatStatus($threatId, $data['status']);
        MySQLRepository::log((int)$user['id'], 'THREAT_STATUS_UPDATED', "Threat #$threatId ({$threat['threatName']}) status: {$threat['status']} -> {$data['status']}", 'threat', (string)$threatId);
        Response::success('Threat status updated', $updated);
    }
}
