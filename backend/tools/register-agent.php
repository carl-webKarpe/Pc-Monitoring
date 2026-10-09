<?php
declare(strict_types=1);

// Registers an authorized lab PC for the MST agent and prints its device token (shown only once).
// Run on the MST server from the project root:
//   php backend/tools/register-agent.php MST-PC-002 LAB-PC-02 [192.168.1.21]
// Running it again for the same device ID issues a NEW token; the old token stops working.
// Revoke a PC (lost, replaced or no longer authorized):
//   php backend/tools/register-agent.php --revoke MST-PC-002

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

if (($argv[1] ?? '') === '--revoke') {
    $deviceId = (string)($argv[2] ?? '');
    $computer = preg_match('/^[A-Za-z0-9._-]{3,40}$/', $deviceId) ? MySQLRepository::findComputerForAgent($deviceId) : null;
    if (!$computer) { fwrite(STDERR, "Unknown device ID.\n"); exit(2); }
    MySQLRepository::revokeAgent((int)$computer['id']);
    MySQLRepository::log(null, 'AGENT_REVOKED', "Revoked the agent token of $deviceId", 'computer', (string)$computer['id']);
    echo "Agent token for $deviceId revoked. That PC can no longer send data until it is registered again.\n";
    exit(0);
}

[$script, $deviceId, $hostname, $ipAddress] = array_pad($argv, 4, null);
if ($deviceId === null || $hostname === null) {
    fwrite(STDERR, "Usage: php backend/tools/register-agent.php <DEVICE-ID> <HOSTNAME> [IP-ADDRESS]\nExample: php backend/tools/register-agent.php MST-PC-002 LAB-PC-02 192.168.1.21\n");
    exit(2);
}
if (!preg_match('/^[A-Za-z0-9._-]{3,40}$/', $deviceId)) { fwrite(STDERR, "Invalid device ID: use 3-40 letters, numbers, dots, dashes or underscores.\n"); exit(2); }
if (!preg_match('/^[A-Za-z0-9._-]{1,120}$/', $hostname)) { fwrite(STDERR, "Invalid hostname.\n"); exit(2); }
if ($ipAddress !== null && !filter_var($ipAddress, FILTER_VALIDATE_IP)) { fwrite(STDERR, "Invalid IP address.\n"); exit(2); }

try {
    $token = bin2hex(random_bytes(32));
    [$computerId, $created, $replaced] = MySQLRepository::registerAgent($deviceId, $hostname, $ipAddress ?? '0.0.0.0', hash('sha256', $token));
    MySQLRepository::log(null, $replaced ? 'AGENT_TOKEN_ROTATED' : 'AGENT_REGISTERED', ($replaced ? 'Issued a new agent token for ' : 'Registered agent for ') . $deviceId, 'computer', (string)$computerId);
} catch (Throwable $exception) {
    fwrite(STDERR, "Could not register the agent: " . $exception->getMessage() . "\nCheck that MySQL is running, .env is correct and database/migrations/phase9_agent.sql has been applied.\n");
    exit(1);
}

echo ($created ? 'Registered new computer' : ($replaced ? 'Existing computer found - issued a NEW token (the old one no longer works)' : 'Existing computer found - agent token created')) . " #$computerId ($deviceId).\n\n";
echo "Put these two lines in agent/config.json on that lab PC:\n";
echo "  \"device_id\": \"$deviceId\",\n";
echo "  \"device_token\": \"$token\",\n\n";
echo "The token is shown only once. Keep it private.\n";
