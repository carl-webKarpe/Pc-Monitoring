<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

// Authenticates a lab-PC agent: X-Device-Id header + "Authorization: Bearer <device token>".
// Only a SHA-256 hash of each token is stored in computers.agent_token_hash.
final class AgentAuth
{
    public static function requireDevice(): array
    {
        $deviceId = (string)($_SERVER['HTTP_X_DEVICE_ID'] ?? '');
        $header = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        $token = preg_match('/^Bearer\s+([A-Za-z0-9]{32,128})$/', $header, $match) ? $match[1] : '';
        $computer = ($token !== '' && preg_match('/^[A-Za-z0-9._-]{3,40}$/', $deviceId)) ? MySQLRepository::findComputerForAgent($deviceId) : null;
        if (!$computer || empty($computer['agentTokenHash']) || !hash_equals($computer['agentTokenHash'], hash('sha256', $token))) {
            Response::error('Device not authorized', 'DEVICE_UNAUTHORIZED', 401);
        }
        unset($computer['agentTokenHash']);
        return $computer;
    }
}
