<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validation.php';
require_once __DIR__ . '/../middleware/AgentAuth.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

// Endpoints used by the Python monitoring agent on each lab PC (device-token authentication, no user session).
final class AgentController
{
    private const MAX_BODY_BYTES = 1048576;
    private const MAX_EVENTS = 100;

    public static function index(string $method, ?string $action): never
    {
        if ($method !== 'POST') Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
        if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > self::MAX_BODY_BYTES) Response::error('Request too large', 'PAYLOAD_TOO_LARGE', 413);
        if ($action === 'heartbeat') self::heartbeat();
        if ($action === 'events') self::events();
        Response::error('Endpoint not found', 'NOT_FOUND', 404);
    }

    private static function heartbeat(): never
    {
        $computer = AgentAuth::requireDevice();
        $data = Validation::body();
        $errors = [];
        $text = static function (string $field, int $max, bool $required = true) use ($data, &$errors): ?string {
            $value = $data[$field] ?? null;
            if ($value === null || $value === '') { if ($required) $errors[$field] = "$field is required"; return null; }
            if (!is_string($value) || !preg_match('//u', $value) || strlen($value) > $max || preg_match('/[\x00-\x1F\x7F<>]/', $value)) { $errors[$field] = "$field is invalid"; return null; }
            return trim($value);
        };
        $percent = static function (string $field) use ($data, &$errors): ?int {
            $value = $data[$field] ?? null;
            if ($value === null) return null;
            if (!is_int($value) || $value < 0 || $value > 100) { $errors[$field] = "$field must be 0-100"; return null; }
            return $value;
        };
        $clean = [
            'hostname' => $text('hostname', 120),
            'ipAddress' => $text('ipAddress', 45),
            'macAddress' => $text('macAddress', 17, false),
            'operatingSystem' => $text('operatingSystem', 80),
            'agentVersion' => $text('agentVersion', 20),
            'cpuUsage' => $percent('cpuUsage'),
            'memoryUsage' => $percent('memoryUsage'),
            'diskUsage' => $percent('diskUsage'),
        ];
        if ($clean['ipAddress'] !== null && !filter_var($clean['ipAddress'], FILTER_VALIDATE_IP)) $errors['ipAddress'] = 'ipAddress is invalid';
        if ($clean['macAddress'] !== null && !preg_match('/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/i', $clean['macAddress'])) $errors['macAddress'] = 'macAddress is invalid';
        if ($errors !== []) Validation::fail($errors);
        MySQLRepository::recordHeartbeat((int)$computer['id'], $clean);
        Response::success('Heartbeat recorded', ['deviceId' => $computer['deviceId'], 'serverTime' => date('c')]);
    }

    private static function events(): never
    {
        $computer = AgentAuth::requireDevice();
        $data = Validation::body();
        if (!isset($data['events']) || !is_array($data['events']) || !array_is_list($data['events'])) Validation::fail(['events' => 'events must be a list']);
        if (count($data['events']) > self::MAX_EVENTS) Validation::fail(['events' => 'At most ' . self::MAX_EVENTS . ' events per request']);
        $valid = []; $rejected = 0;
        foreach ($data['events'] as $event) {
            $clean = is_array($event) ? self::cleanEvent($event) : null;
            if ($clean === null) { $rejected++; continue; }
            $valid[] = $clean;
        }
        [$accepted, $duplicates] = $valid === [] ? [0, 0] : MySQLRepository::insertFileEvents((int)$computer['id'], $valid);
        if ($rejected > 0) error_log("Agent {$computer['deviceId']}: rejected $rejected invalid file event(s)");
        // Invalid events are reported but not retried, so one bad event cannot block the agent's queue.
        Response::success('Events received', ['accepted' => $accepted, 'duplicates' => $duplicates, 'rejected' => $rejected]);
    }

    private static function cleanEvent(array $event): ?array
    {
        $uid = $event['uid'] ?? null; $type = $event['type'] ?? null; $name = $event['fileName'] ?? null; $path = $event['filePath'] ?? null;
        $size = $event['fileSize'] ?? null; $sha256 = $event['sha256'] ?? null; $detected = $event['detectedAt'] ?? null;
        if (!is_string($uid) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uid)) return null;
        if (!in_array($type, ['created', 'deleted'], true)) return null;
        foreach ([[$name, 255], [$path, 1024]] as [$value, $max]) if (!is_string($value) || $value === '' || strlen($value) > $max || !preg_match('//u', $value) || preg_match('/[\x00-\x1F\x7F]/', $value)) return null;
        if ($size !== null && (!is_int($size) || $size < 0)) return null;
        if ($sha256 !== null && (!is_string($sha256) || !preg_match('/^[0-9a-f]{64}$/i', $sha256))) return null;
        if (!is_string($detected)) return null;
        try { $time = new DateTimeImmutable($detected); } catch (Exception) { return null; }
        // Store in the server's local time, like the rest of the MST timestamps; reject clearly wrong clocks.
        $time = $time->setTimezone(new DateTimeZone(date_default_timezone_get()));
        if ($time > new DateTimeImmutable('+1 day') || $time < new DateTimeImmutable('-1 year')) return null;
        return ['uid' => strtolower($uid), 'type' => $type, 'fileName' => $name, 'filePath' => $path, 'fileSize' => $size, 'sha256' => $sha256 === null ? null : strtolower($sha256), 'detectedAt' => $time->format('Y-m-d H:i:s')];
    }
}
