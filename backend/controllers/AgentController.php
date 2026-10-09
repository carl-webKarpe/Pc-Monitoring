<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validation.php';
require_once __DIR__ . '/../middleware/AgentAuth.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';
require_once __DIR__ . '/../services/ScanService.php';

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
        if ($action === 'scan-jobs') self::scanJobs();
        if ($action === 'scan-results') self::scanResult();
        if ($action === 'action-results') self::actionResult();
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
            if (!is_string($value) || !preg_match('/^.{1,' . $max . '}$/us', $value) || preg_match('/[\x00-\x1F\x7F<>]/', $value)) { $errors[$field] = "$field is invalid"; return null; }
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
        [$accepted, $duplicates, $stored] = $valid === [] ? [0, 0, []] : MySQLRepository::insertFileEvents((int)$computer['id'], $valid);
        if ($rejected > 0) error_log("Agent {$computer['deviceId']}: rejected $rejected invalid file event(s)");
        $autoScans = ScanService::autoScan($stored, (string)$computer['hostname']);
        // Invalid events are reported but not retried, so one bad event cannot block the agent's queue.
        Response::success('Events received', ['accepted' => $accepted, 'duplicates' => $duplicates, 'rejected' => $rejected, 'autoScans' => $autoScans]);
    }

    // Scans (requested by an Admin or automatic) and quarantine actions for this computer.
    // The agent only touches paths inside its own watch folders and quarantine folder.
    private static function scanJobs(): never
    {
        $computer = AgentAuth::requireDevice();
        Response::success('Scan jobs', ['jobs' => MySQLRepository::scanJobs((int)$computer['id']), 'actions' => MySQLRepository::quarantineJobs((int)$computer['id'])]);
    }

    private static function scanResult(): never
    {
        $computer = AgentAuth::requireDevice();
        $data = Validation::body();
        $scanId = $data['scanId'] ?? null;
        $outcome = $data['outcome'] ?? null;
        $sha256 = $data['sha256'] ?? null;
        $durationMs = $data['durationMs'] ?? 0;
        $errors = [];
        if (!is_int($scanId) || $scanId < 1) $errors['scanId'] = 'scanId is required';
        if (!in_array($outcome, ['completed', 'failed'], true)) $errors['outcome'] = 'outcome must be completed or failed';
        if ($sha256 !== null && (!is_string($sha256) || !preg_match('/^[0-9a-f]{64}$/i', $sha256))) $errors['sha256'] = 'sha256 is invalid';
        if (!is_int($durationMs) || $durationMs < 0) $errors['durationMs'] = 'durationMs is invalid';
        if (isset($data['engines']) && !is_array($data['engines'])) $errors['engines'] = 'engines must be a list';
        if ($errors !== []) Validation::fail($errors);
        $scan = MySQLRepository::findPendingScan($scanId, (int)$computer['id']);
        // Already finished (e.g. a retried request) or not this computer's scan: acknowledge without changes.
        if (!$scan) Response::success('Scan result ignored', ['scanId' => $scanId, 'ignored' => true]);
        $result = ScanService::finishAgentScan($scan, $data, $sha256 === null ? null : strtolower($sha256), min($durationMs, 86400000));
        Response::success('Scan result recorded', ['scanId' => $scanId, 'scanState' => $result['scanState'] ?? null, 'riskLevel' => $result['riskLevel'] ?? null]);
    }

    // The agent's answer to a quarantine / release / delete job.
    private static function actionResult(): never
    {
        $computer = AgentAuth::requireDevice();
        $data = Validation::body();
        $itemId = $data['itemId'] ?? null; $action = $data['action'] ?? null; $outcome = $data['outcome'] ?? null; $name = $data['quarantineName'] ?? null;
        $errors = [];
        if (!is_int($itemId) || $itemId < 1) $errors['itemId'] = 'itemId is required';
        if (!in_array($action, ['quarantine', 'release', 'delete'], true)) $errors['action'] = 'action must be quarantine, release or delete';
        if (!in_array($outcome, ['completed', 'failed'], true)) $errors['outcome'] = 'outcome must be completed or failed';
        if ($name !== null && (!is_string($name) || !preg_match('/^[A-Za-z0-9._-]{1,160}$/', $name))) $errors['quarantineName'] = 'quarantineName is invalid';
        if ($errors !== []) Validation::fail($errors);
        $item = MySQLRepository::pendingQuarantineItem($itemId, (int)$computer['id'], $action);
        if (!$item) Response::success('Action result ignored', ['itemId' => $itemId, 'ignored' => true]);
        $succeeded = $outcome === 'completed';
        $error = $succeeded ? null : (ScanService::cleanText($data['error'] ?? '', 200) ?: 'The agent could not complete the action');
        $updated = MySQLRepository::finishQuarantineAction($item, $action, $succeeded, $name, $error);
        $verb = ['quarantine' => 'Quarantined', 'release' => 'Released', 'delete' => 'Deleted'][$action];
        MySQLRepository::log(null, $succeeded ? ['quarantine' => 'FILE_QUARANTINED', 'release' => 'FILE_RELEASED', 'delete' => 'QUARANTINE_DELETED'][$action] : 'QUARANTINE_FAILED', $succeeded ? "$verb {$item['fileName']} on {$computer['hostname']}" : ucfirst($action) . " of {$item['fileName']} on {$computer['hostname']} failed: $error", 'quarantine', (string)$itemId);
        Response::success('Action result recorded', ['itemId' => $itemId, 'status' => $updated['status'] ?? null]);
    }

    private static function cleanEvent(array $event): ?array
    {
        $uid = $event['uid'] ?? null; $type = $event['type'] ?? null; $name = $event['fileName'] ?? null; $path = $event['filePath'] ?? null; $previous = $event['previousPath'] ?? null;
        $size = $event['fileSize'] ?? null; $sha256 = $event['sha256'] ?? null; $detected = $event['detectedAt'] ?? null; $origin = $event['origin'] ?? null;
        if (!is_string($uid) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uid)) return null;
        if (!in_array($type, ['created', 'modified', 'renamed', 'deleted'], true)) return null;
        $validPath = static fn($value, int $max): bool => is_string($value) && $value !== '' && preg_match('/^.{1,' . $max . '}$/us', $value) && !preg_match('/[\x00-\x1F\x7F]/', $value);
        if (!$validPath($name, 255) || !$validPath($path, 1024)) return null;
        if ($type === 'renamed' ? !$validPath($previous, 1024) : $previous !== null) return null;
        if ($size !== null && (!is_int($size) || $size < 0)) return null;
        if ($sha256 !== null && (!is_string($sha256) || !preg_match('/^[0-9a-f]{64}$/i', $sha256))) return null;
        if ($origin !== null && !in_array($origin, ['local', 'browser_download', 'internet'], true)) return null;
        if (!is_string($detected)) return null;
        try { $time = new DateTimeImmutable($detected); } catch (Exception) { return null; }
        // Store in the server's local time, like the rest of the MST timestamps; reject clearly wrong clocks.
        $time = $time->setTimezone(new DateTimeZone(date_default_timezone_get()));
        if ($time > new DateTimeImmutable('+1 day') || $time < new DateTimeImmutable('-1 year')) return null;
        return ['uid' => strtolower($uid), 'type' => $type, 'fileName' => $name, 'filePath' => $path, 'previousPath' => $previous, 'fileSize' => $size, 'sha256' => $sha256 === null ? null : strtolower($sha256),
            'detectedAt' => $time->format('Y-m-d H:i:s'), 'origin' => $type === 'deleted' ? null : $origin, 'downloadUrl' => $type === 'deleted' ? null : ScanService::cleanUrl($event['downloadUrl'] ?? null)];
    }
}
