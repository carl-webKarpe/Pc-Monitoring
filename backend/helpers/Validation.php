<?php
declare(strict_types=1);

require_once __DIR__ . '/Security.php';

final class Validation
{
    public const ACCOUNT_STATUSES = ['Active', 'Inactive', 'Suspended'];

    public const MAX_BODY_BYTES = 1048576; // 1 MB is far more than any MST request needs

    public static function body(): array
    {
        if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > self::MAX_BODY_BYTES) Response::error('Request too large', 'PAYLOAD_TOO_LARGE', 413);
        $raw = file_get_contents('php://input', false, null, 0, self::MAX_BODY_BYTES + 1);
        if ($raw !== false && strlen($raw) > self::MAX_BODY_BYTES) Response::error('Request too large', 'PAYLOAD_TOO_LARGE', 413);
        if ($raw === false || trim($raw) === '') return [];
        $data = json_decode($raw, true);
        if (!is_array($data)) Response::error('Invalid JSON body', 'INVALID_JSON', 400);
        return $data;
    }

    // mbstring is optional on plain Windows PHP installs; fall back to byte length when it is missing.
    private static function length(string $value): int { return function_exists('mb_strlen') ? mb_strlen($value) : strlen($value); }

    public static function fail(array $errors): never { Response::error('Validation failed', 'VALIDATION_FAILED', 422, $errors); }

    public static function required(array $data, array $fields): void
    {
        $errors = [];
        foreach ($fields as $field) if (!isset($data[$field]) || !is_scalar($data[$field]) || trim((string)$data[$field]) === '') $errors[$field] = $field . ' is required';
        if ($errors !== []) self::fail($errors);
    }

    public static function login(array $data): void { self::required($data, ['username', 'password']); }

    // Create requires every account field; update ($partial) validates only the fields that were sent.
    public static function resource(array $data, string $resource, bool $partial = false, bool $strongPassword = true): void
    {
        if (!$partial) self::required($data, ['firstName', 'lastName', 'email', 'username', 'password']);
        $errors = [];
        foreach (['firstName', 'middleName', 'lastName', 'email', 'username', 'password', 'status', 'role'] as $field) if (array_key_exists($field, $data) && $data[$field] !== null && !is_scalar($data[$field])) $errors[$field] = $field . ' is invalid';
        if ($errors !== []) self::fail($errors);
        foreach (['firstName', 'lastName'] as $field) if (isset($data[$field]) && (trim((string)$data[$field]) === '' || self::length(trim((string)$data[$field])) > 80)) $errors[$field] = $field . ' must be 1-80 characters';
        if (isset($data['middleName']) && self::length(trim((string)$data['middleName'])) > 80) $errors['middleName'] = 'middleName must be at most 80 characters';
        if (isset($data['email']) && (!filter_var((string)$data['email'], FILTER_VALIDATE_EMAIL) || strlen((string)$data['email']) > 190)) $errors['email'] = 'Email is invalid';
        if (isset($data['username']) && !preg_match('/^[A-Za-z0-9._-]{3,40}$/', (string)$data['username'])) $errors['username'] = 'Username must be 3-40 characters';
        if ((!$partial || (isset($data['password']) && $data['password'] !== '')) && ($problem = Security::passwordProblem((string)$data['password'], (string)($data['username'] ?? ''), $strongPassword)) !== null) $errors['password'] = $problem;
        if (isset($data['status']) && !in_array($data['status'], self::ACCOUNT_STATUSES, true)) $errors['status'] = 'Status must be Active, Inactive, or Suspended';
        if ($resource === 'users' && isset($data['role']) && $data['role'] !== 'Tenant') $errors['role'] = 'User role must be Tenant';
        if ($resource === 'admins' && isset($data['role']) && $data['role'] !== 'Admin') $errors['role'] = 'New administrators must use the Admin role';
        if ($errors !== []) self::fail($errors);
    }

    // Settings allowlist: key => [category, type]. Only these keys can be stored.
    public const SETTINGS = [
        'systemName' => ['system', 'text'], 'timeZone' => ['system', 'text'], 'refreshInterval' => ['system', 'duration'],
        'monitoringStatus' => ['monitoring', 'bool'], 'heartbeat' => ['monitoring', 'duration'], 'offlineThreshold' => ['monitoring', 'duration'], 'threatNotifications' => ['monitoring', 'bool'],
        'sessionTimeout' => ['security', 'duration'], 'loginLimit' => ['security', 'attempts'], 'strongPassword' => ['security', 'bool'], 'twoFactor' => ['security', 'bool'],
        'threatAlerts' => ['notifications', 'bool'], 'offlineAlerts' => ['notifications', 'bool'], 'agentAlerts' => ['notifications', 'bool'], 'systemNotifications' => ['notifications', 'bool'],
        'compactMode' => ['interface', 'bool'], 'animations' => ['interface', 'bool'],
    ];

    /** @return array<string, array{0: string, 1: string}> key => [category, normalized value] */
    public static function settings(array $data): array
    {
        if ($data === []) self::fail(['settings' => 'At least one setting is required']);
        $errors = []; $clean = [];
        foreach ($data as $key => $value) {
            $rule = self::SETTINGS[$key] ?? null;
            if ($rule === null) { $errors[$key] = 'Unknown setting'; continue; }
            [$category, $type] = $rule;
            if ($type === 'bool') {
                if (!in_array($value, [true, false, 0, 1, '0', '1'], true)) { $errors[$key] = 'Must be true or false'; continue; }
                $clean[$key] = [$category, in_array($value, [true, 1, '1'], true) ? '1' : '0'];
                continue;
            }
            $text = is_scalar($value) ? trim((string)$value) : '';
            $valid = match ($type) {
                'duration' => (bool)preg_match('/^\d{1,4} (seconds?|minutes?|hours?)$/i', $text),
                'attempts' => (bool)preg_match('/^\d{1,3} attempts?$/i', $text),
                default => $text !== '' && self::length($text) <= 100 && !preg_match('/[\x00-\x1F\x7F<>]/u', $text),
            };
            if (!$valid) { $errors[$key] = match ($type) { 'duration' => 'Use a value such as "10 seconds" or "30 minutes"', 'attempts' => 'Use a value such as "5 attempts"', default => 'Must be 1-100 characters without < or >' }; continue; }
            $clean[$key] = [$category, $text];
        }
        if ($errors !== []) self::fail($errors);
        return $clean;
    }

    /** @return array{0: int, 1: int} [limit, offset] from ?limit=&offset= */
    public static function page(int $defaultLimit = 500, int $maxLimit = 500): array
    {
        $limit = $_GET['limit'] ?? (string)$defaultLimit; $offset = $_GET['offset'] ?? '0';
        if (!is_string($limit) || !ctype_digit($limit) || (int)$limit < 1 || (int)$limit > $maxLimit) self::fail(['limit' => "limit must be between 1 and $maxLimit"]);
        if (!is_string($offset) || !ctype_digit($offset) || strlen($offset) > 9) self::fail(['offset' => 'offset must be a non-negative number']);
        return [(int)$limit, (int)$offset];
    }

    /** Optional allowlisted query filters, e.g. ?severity=HIGH&status=Detected. Maps query parameter => [column, allowed values]. */
    public static function filters(array $allowed): array
    {
        $filters = []; $errors = [];
        foreach ($allowed as $parameter => [$column, $values]) {
            if (!isset($_GET[$parameter]) || $_GET[$parameter] === '') continue;
            $value = $_GET[$parameter];
            if ($values === 'id') { if (!is_string($value) || !ctype_digit($value) || (int)$value < 1) { $errors[$parameter] = "$parameter must be a positive number"; continue; } $filters[$column] = (int)$value; continue; }
            if (!is_string($value) || !in_array($value, $values, true)) { $errors[$parameter] = "$parameter must be one of: " . implode(', ', $values); continue; }
            $filters[$column] = $value;
        }
        if ($errors !== []) self::fail($errors);
        return $filters;
    }

    public static function id(string $id): int { if (!ctype_digit($id) || (int)$id < 1) Response::error('Invalid resource ID', 'INVALID_ID', 422); return (int)$id; }
}
