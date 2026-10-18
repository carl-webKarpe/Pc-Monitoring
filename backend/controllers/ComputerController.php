<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';
require_once __DIR__ . '/PhoneAuthController.php';

final class ComputerController
{
    public static function index(string $method, ?string $id = null, ?string $action = null): never
    {
        // Register one PC from the website (Computers > Add Computers > One PC); new token / revoke for a registered PC.
        if ($id === null && $action === null && $method === 'POST') self::register();
        if ($id !== null && $action === 'token' && $method === 'POST') self::newToken($id);
        if ($id !== null && $action === 'revoke' && $method === 'POST') self::revoke($id);
        if ($method !== 'GET' || $action !== null) Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        if ($id === null) ResourceController::list('computers');
        ResourceController::show('computers', $id);
    }

    private static function register(): never
    {
        $user = RoleMiddleware::allowModule('computer_monitoring');
        $name = trim((string)(Validation::body()['name'] ?? ''));
        if (!preg_match('/^[^\x00-\x1F\x7F<>]{1,120}$/u', $name)) Validation::fail(['name' => 'Enter a computer name (up to 120 characters, without < or >)']);
        $token = bin2hex(random_bytes(32));
        $deviceId = MySQLRepository::nextDeviceId();
        [$computerId] = MySQLRepository::registerAgent($deviceId, $name, '0.0.0.0', hash('sha256', $token));
        MySQLRepository::log((int)$user['id'], 'AGENT_REGISTERED', "Registered $name as $deviceId from the website", 'computer', (string)$computerId);
        self::tokenResponse('Computer registered. Copy the token now: it is shown only once.', $computerId, $deviceId, $token, 201);
    }

    private static function newToken(string $id): never
    {
        $user = RoleMiddleware::allowModule('computer_monitoring');
        $computer = self::findOrFail($id);
        $token = bin2hex(random_bytes(32));
        MySQLRepository::registerAgent($computer['deviceId'], $computer['hostname'], $computer['ipAddress'], hash('sha256', $token));
        MySQLRepository::log((int)$user['id'], 'AGENT_TOKEN_ROTATED', "Issued a new agent token for {$computer['deviceId']} ({$computer['hostname']}); the old token stopped working", 'computer', (string)$computer['id']);
        self::tokenResponse('New token created. The old token no longer works: put the new config.json on that PC.', (int)$computer['id'], $computer['deviceId'], $token, 200);
    }

    private static function revoke(string $id): never
    {
        $user = RoleMiddleware::allowModule('computer_monitoring');
        $computer = self::findOrFail($id);
        if ((Validation::body()['confirm'] ?? false) !== true) Validation::fail(['confirm' => 'Confirm that this PC should stop sending data']);
        MySQLRepository::revokeAgent((int)$computer['id']);
        MySQLRepository::log((int)$user['id'], 'AGENT_REVOKED', "Revoked the agent token of {$computer['deviceId']} ({$computer['hostname']})", 'computer', (string)$computer['id']);
        Response::success('Agent access revoked. The PC can no longer send data until it gets a new token. Its history is kept.', MySQLRepository::find('computers', (int)$computer['id']));
    }

    private static function findOrFail(string $id): array
    {
        $computer = MySQLRepository::find('computers', Validation::id($id));
        if (!$computer) Response::error('Computer not found', 'NOT_FOUND', 404);
        return $computer;
    }

    /** The token is returned once, with a ready config.json for the agent (agent/config.example.json + this PC's values). */
    private static function tokenResponse(string $message, int $computerId, string $deviceId, string $token, int $status): never
    {
        $serverUrl = PhoneAuthController::publicApiUrl();
        $example = json_decode((string)@file_get_contents(__DIR__ . '/../../agent/config.example.json'), true);
        $config = array_merge(is_array($example) ? $example : ['watch_folders' => ['{Downloads}', '{Desktop}', '{Documents}']], ['server_url' => $serverUrl, 'device_id' => $deviceId, 'device_token' => $token]);
        Response::success($message, ['computerId' => $computerId, 'deviceId' => $deviceId, 'deviceToken' => $token, 'serverUrl' => $serverUrl, 'config' => $config], $status);
    }
}
