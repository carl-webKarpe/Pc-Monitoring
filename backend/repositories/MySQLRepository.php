<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../helpers/FileRisk.php';
require_once __DIR__ . '/../helpers/VirusTotal.php';

final class MySQLRepository
{
    // Tenants are managed through /users and administrators through /admins; each endpoint only sees its own roles.
    private const ACCOUNT_ROLES = ['users' => ['Tenant'], 'admins' => ['Admin', 'Super Admin']];
    private const REMOVABLE_ROLES = ['users' => ['Tenant'], 'admins' => ['Admin']];

    // Joined read models for the monitoring resources. Table and column names below are fixed; user values are always bound.
    private const COMPUTER_SELECT = "SELECT c.*,
        (SELECT COUNT(*) FROM threats t WHERE t.computer_id = c.id AND t.status NOT IN ('Resolved', 'Ignored')) AS active_threats,
        (SELECT COUNT(*) FROM scans s WHERE s.computer_id = c.id) AS scan_count,
        (SELECT MAX(COALESCE(s.completed_at, s.created_at)) FROM scans s WHERE s.computer_id = c.id) AS last_scan_at
        FROM computers c";
    private const THREAT_SELECT = 'SELECT t.*, c.hostname AS computer_hostname, c.device_id AS computer_device_id, c.ip_address AS computer_ip_address, c.status AS computer_status
        FROM threats t LEFT JOIN computers c ON c.id = t.computer_id';
    private const SCAN_SELECT = 'SELECT s.*, c.hostname AS computer_hostname, c.device_id AS computer_device_id, u.username AS created_by_username
        FROM scans s LEFT JOIN computers c ON c.id = s.computer_id LEFT JOIN users u ON u.id = s.created_by';
    private const RESOURCES = ['computers' => [self::COMPUTER_SELECT, 'c'], 'threats' => [self::THREAT_SELECT, 't'], 'scans' => [self::SCAN_SELECT, 's']];
    private const FILTERABLE = ['threats' => ['severity', 'status', 'computer_id'], 'scans' => ['status', 'scan_type', 'computer_id'], 'file_events' => ['computer_id', 'event_type', 'status']];
    private const FILE_EVENT_SELECT = 'SELECT f.*, c.hostname AS computer_hostname, c.device_id AS computer_device_id, c.ip_address AS computer_ip_address, c.status AS computer_status, s.status AS scan_status, s.completed_at AS scan_completed_at, s.scan_details AS scan_details FROM file_events f JOIN computers c ON c.id = f.computer_id LEFT JOIN scans s ON s.id = f.scan_id';

    private static array $permissionCache = [];

    private static function db(): PDO { return Database::connection(); }
    private static function map(array $row): array { foreach ($row as $key => $value) { $camel = preg_replace_callback('/_([a-z])/', fn($m) => strtoupper($m[1]), $key); if ($camel !== $key) { $row[$camel] = $value; unset($row[$key]); } } return $row; }
    private static function public(array $row): array { unset($row['passwordHash'], $row['agentTokenHash']); return $row; }
    private static function roleClause(array $roles): string { return 'role IN (' . implode(', ', array_fill(0, count($roles), '?')) . ')'; }
    private static function optionalText(array $data, string $field): ?string { return isset($data[$field]) && trim((string)$data[$field]) !== '' ? trim((string)$data[$field]) : null; }
    private static function fetchAll(string $sql, array $params = []): array { $statement = self::db()->prepare($sql); $statement->execute($params); return array_map(fn($row) => self::public(self::map($row)), $statement->fetchAll()); }
    private static function fetchOne(string $sql, array $params): ?array { $statement = self::db()->prepare($sql); $statement->execute($params); $row = $statement->fetch(); return $row ? self::public(self::map($row)) : null; }

    public static function list(string $resource, array $filters = [], int $limit = 500, int $offset = 0): array
    {
        $page = ' LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset);
        if (isset(self::ACCOUNT_ROLES[$resource])) { $roles = self::ACCOUNT_ROLES[$resource]; return self::fetchAll('SELECT * FROM users WHERE ' . self::roleClause($roles) . ' ORDER BY id DESC' . $page, $roles); }
        if ($resource === 'computers') self::markStaleComputersOffline();
        $resources = self::RESOURCES + ['file_events' => [self::FILE_EVENT_SELECT, 'f']];
        if (!isset($resources[$resource])) throw new InvalidArgumentException('Unsupported resource');
        [$select, $alias] = $resources[$resource];
        $conditions = []; $params = [];
        foreach ($filters as $column => $value) {
            if (!in_array($column, self::FILTERABLE[$resource] ?? [], true)) throw new InvalidArgumentException('Unsupported filter');
            $conditions[] = "$alias.$column = ?"; $params[] = $value;
        }
        return self::fetchAll($select . ($conditions ? ' WHERE ' . implode(' AND ', $conditions) : '') . " ORDER BY $alias.id DESC" . $page, $params);
    }

    public static function find(string $resource, int $id): ?array
    {
        if (isset(self::ACCOUNT_ROLES[$resource])) { $roles = self::ACCOUNT_ROLES[$resource]; return self::fetchOne('SELECT * FROM users WHERE id = ? AND ' . self::roleClause($roles), [$id, ...$roles]); }
        if (!isset(self::RESOURCES[$resource])) return null;
        if ($resource === 'computers') self::markStaleComputersOffline();
        [$select, $alias] = self::RESOURCES[$resource];
        return self::fetchOne("$select WHERE $alias.id = ?", [$id]);
    }

    // Accounts: login accepts a username or an email (usernames cannot contain "@", so the two never collide).
    public static function findForLogin(string $login): ?array { $statement = self::db()->prepare('SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1'); $statement->execute([$login, $login]); $row = $statement->fetch(); return $row ? self::map($row) : null; }
    public static function findAccount(int $id): ?array { return self::fetchOne('SELECT * FROM users WHERE id = ?', [$id]); }
    public static function touchLogin(int $id): void { self::db()->prepare('UPDATE users SET last_login = NOW(), updated_at = updated_at WHERE id = ?')->execute([$id]); }
    public static function create(string $resource, array $data): array { if (!isset(self::ACCOUNT_ROLES[$resource])) throw new InvalidArgumentException('Unsupported resource'); $statement = self::db()->prepare('INSERT INTO users (first_name, middle_name, last_name, email, username, password_hash, role, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'); $statement->execute([trim((string)$data['firstName']), self::optionalText($data, 'middleName'), trim((string)$data['lastName']), trim((string)$data['email']), trim((string)$data['username']), password_hash((string)$data['password'], PASSWORD_DEFAULT), $resource === 'admins' ? 'Admin' : 'Tenant', $data['status'] ?? 'Active']); return self::find($resource, (int)self::db()->lastInsertId()) ?? []; }
    public static function update(string $resource, int $id, array $data): array { if (!isset(self::ACCOUNT_ROLES[$resource])) throw new InvalidArgumentException('Unsupported resource'); $roles = self::ACCOUNT_ROLES[$resource]; $statement = self::db()->prepare('UPDATE users SET first_name = COALESCE(?, first_name), middle_name = COALESCE(?, middle_name), last_name = COALESCE(?, last_name), email = COALESCE(?, email), username = COALESCE(?, username), status = COALESCE(?, status), password_hash = COALESCE(?, password_hash), updated_at = NOW() WHERE id = ? AND ' . self::roleClause($roles)); $password = isset($data['password']) && $data['password'] !== '' ? password_hash((string)$data['password'], PASSWORD_DEFAULT) : null; $statement->execute([self::optionalText($data, 'firstName'), self::optionalText($data, 'middleName'), self::optionalText($data, 'lastName'), self::optionalText($data, 'email'), self::optionalText($data, 'username'), $data['status'] ?? null, $password, $id, ...$roles]); return self::find($resource, $id) ?? []; }
    public static function delete(string $resource, int $id): bool { $roles = self::REMOVABLE_ROLES[$resource] ?? null; if ($roles === null) throw new InvalidArgumentException('Unsupported resource'); $statement = self::db()->prepare('DELETE FROM users WHERE id = ? AND ' . self::roleClause($roles)); $statement->execute([$id, ...$roles]); return $statement->rowCount() > 0; }

    public static function updateThreatStatus(int $id, string $status): array { $statement = self::db()->prepare('UPDATE threats SET status = ?, resolved_at = CASE WHEN ? = ? THEN CURRENT_TIMESTAMP ELSE resolved_at END, updated_at = NOW() WHERE id = ?'); $statement->execute([$status, $status, 'Resolved', $id]); return self::find('threats', $id) ?? []; }

    public static function reports(): array
    {
        self::markStaleComputersOffline();
        $db = self::db();
        $computers = $db->query("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'online'), 0) AS online, COALESCE(SUM(status = 'offline'), 0) AS offline, COALESCE(SUM(status = 'warning'), 0) AS warning, COALESCE(SUM(status = 'threat'), 0) AS threat, COALESCE(SUM(agent_status = 'connected'), 0) AS agent_connected FROM computers")->fetch();
        $threats = $db->query("SELECT COUNT(*) AS total, COALESCE(SUM(status NOT IN ('Resolved', 'Ignored')), 0) AS open, COALESCE(SUM(severity = 'CRITICAL'), 0) AS critical, COALESCE(SUM(severity = 'HIGH'), 0) AS high, COALESCE(SUM(severity = 'MEDIUM'), 0) AS medium, COALESCE(SUM(severity = 'LOW'), 0) AS low, COALESCE(SUM(status = 'Resolved'), 0) AS resolved, COALESCE(SUM(severity = 'CRITICAL' AND status NOT IN ('Resolved', 'Ignored')), 0) AS critical_open FROM threats")->fetch();
        $scans = $db->query("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'SAFE'), 0) AS safe, COALESCE(SUM(status = 'THREAT'), 0) AS threat, COALESCE(SUM(status = 'WARNING'), 0) AS warning, COALESCE(SUM(status = 'FAILED'), 0) AS failed FROM scans")->fetch();
        return [
            'totalComputers' => (int)$computers['total'], 'onlineComputers' => (int)$computers['online'], 'offlineComputers' => (int)$computers['offline'], 'warningComputers' => (int)$computers['warning'], 'threatComputers' => (int)$computers['threat'], 'agentConnectedComputers' => (int)$computers['agent_connected'],
            'totalThreats' => (int)$threats['total'], 'openThreats' => (int)$threats['open'], 'criticalThreats' => (int)$threats['critical'], 'openCriticalThreats' => (int)$threats['critical_open'], 'highThreats' => (int)$threats['high'], 'mediumThreats' => (int)$threats['medium'], 'lowThreats' => (int)$threats['low'], 'resolvedThreats' => (int)$threats['resolved'],
            'recentScans' => (int)$scans['total'], 'totalScans' => (int)$scans['total'], 'safeScans' => (int)$scans['safe'], 'threatScans' => (int)$scans['threat'], 'warningScans' => (int)$scans['warning'], 'failedScans' => (int)$scans['failed'],
        ];
    }

    public static function activity(int $limit = 100, int $offset = 0): array { return self::fetchAll('SELECT a.*, u.username, u.role AS user_role FROM activity_logs a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset)); }
    public static function log(?int $userId, string $action, string $description = '', ?string $targetType = null, ?string $targetId = null): void
    {
        // Audit logging must never break the request that triggered it.
        try { self::db()->prepare('INSERT INTO activity_logs (user_id, action, description, target_type, target_id, ip_address) VALUES (?, ?, ?, ?, ?, ?)')->execute([$userId, $action, (function_exists('mb_substr') ? mb_substr($description, 0, 255) : substr($description, 0, 255)), $targetType, $targetId, substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45) ?: null]); }
        catch (Throwable $exception) { error_log('Activity log failed: ' . $exception->getMessage()); }
    }

    public static function permissions(): array { $result = []; foreach (self::db()->query('SELECT role, module, allowed FROM permissions ORDER BY id')->fetchAll() as $row) $result[$row['role']][$row['module']] = (bool)$row['allowed']; return $result; }
    public static function permissionFor(string $role, string $module): ?bool
    {
        if (!array_key_exists("$role|$module", self::$permissionCache)) { $statement = self::db()->prepare('SELECT allowed FROM permissions WHERE role = ? AND module = ? LIMIT 1'); $statement->execute([$role, $module]); $value = $statement->fetchColumn(); self::$permissionCache["$role|$module"] = $value === false ? null : (bool)$value; }
        return self::$permissionCache["$role|$module"];
    }
    public static function savePermissions(string $role, array $permissions): array { $statement = self::db()->prepare('INSERT INTO permissions (role, module, allowed) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE allowed = VALUES(allowed)'); foreach ($permissions as $module => $allowed) $statement->execute([$role, (string)$module, $allowed ? 1 : 0]); self::$permissionCache = []; return self::permissions(); }

    private static array $settingCache = [];
    public static function setting(string $key): ?string
    {
        if (!array_key_exists($key, self::$settingCache)) { $statement = self::db()->prepare('SELECT setting_value FROM settings WHERE setting_key = ?'); $statement->execute([$key]); $value = $statement->fetchColumn(); self::$settingCache[$key] = $value === false ? null : (string)$value; }
        return self::$settingCache[$key];
    }

    /** Failed logins in the last $minutes for this account (since its last successful login) and for this IP address. @return array{0: int, 1: int} */
    public static function recentLoginFailures(?int $userId, ?string $ip, int $minutes): array
    {
        $byAccount = 0; $byIp = 0;
        if ($userId !== null) {
            $statement = self::db()->prepare("SELECT COUNT(*) FROM activity_logs WHERE action = 'LOGIN_FAILED' AND user_id = ? AND created_at > NOW() - INTERVAL ? MINUTE AND id > COALESCE((SELECT MAX(id) FROM activity_logs WHERE action = 'LOGIN' AND user_id = ?), 0)");
            $statement->execute([$userId, $minutes, $userId]); $byAccount = (int)$statement->fetchColumn();
        }
        if ($ip !== null) {
            $statement = self::db()->prepare("SELECT COUNT(*) FROM activity_logs WHERE action = 'LOGIN_FAILED' AND ip_address = ? AND created_at > NOW() - INTERVAL ? MINUTE");
            $statement->execute([$ip, $minutes]); $byIp = (int)$statement->fetchColumn();
        }
        return [$byAccount, $byIp];
    }

    public static function settings(): array { $result = []; foreach (self::db()->query('SELECT setting_key, setting_value FROM settings')->fetchAll() as $row) $result[$row['setting_key']] = $row['setting_value']; return $result; }
    public static function saveSettings(array $settings): array { $statement = self::db()->prepare('INSERT INTO settings (category, setting_key, setting_value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = CURRENT_TIMESTAMP'); foreach ($settings as $key => [$category, $value]) $statement->execute([$category, $key, $value]); self::$settingCache = []; return self::settings(); }

    // ---- Agent (Phase 9) -------------------------------------------------------------------------------

    // A computer whose agent stopped sending heartbeats is shown offline after the "Offline Threshold" setting (minimum 45 s).
    public static function markStaleComputersOffline(): void
    {
        $seconds = 90;
        $setting = self::db()->query("SELECT setting_value FROM settings WHERE setting_key = 'offlineThreshold'")->fetchColumn();
        if ($setting !== false && preg_match('/^(\d{1,4}) (second|minute|hour)s?$/i', trim((string)$setting), $match)) $seconds = (int)$match[1] * ['second' => 1, 'minute' => 60, 'hour' => 3600][strtolower($match[2])];
        self::db()->prepare("UPDATE computers SET status = 'offline', agent_status = 'disconnected' WHERE agent_status = 'connected' AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at < NOW() - INTERVAL ? SECOND")->execute([max(45, $seconds)]);
    }

    // Includes the token hash: only for AgentAuth, never returned to clients.
    public static function findComputerForAgent(string $deviceId): ?array { $statement = self::db()->prepare('SELECT id, device_id, hostname, agent_token_hash FROM computers WHERE device_id = ? LIMIT 1'); $statement->execute([$deviceId]); $row = $statement->fetch(); return $row ? self::map($row) : null; }

    public static function recordHeartbeat(int $computerId, array $data): void
    {
        // Online status also reflects open threats: CRITICAL/HIGH -> threat, other open threats -> warning.
        $openThreat = "EXISTS (SELECT 1 FROM threats t WHERE t.computer_id = computers.id AND t.status NOT IN ('Resolved', 'Ignored')";
        self::db()->prepare("UPDATE computers SET hostname = ?, ip_address = ?, mac_address = ?, operating_system = ?, agent_version = ?, cpu_usage = ?, memory_usage = ?, disk_usage = ?,
            agent_status = 'connected', last_heartbeat_at = NOW(), last_seen = DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i:%s'),
            status = CASE WHEN $openThreat AND t.severity IN ('CRITICAL', 'HIGH')) THEN 'threat' WHEN $openThreat) THEN 'warning' ELSE 'online' END,
            threat_level = CASE WHEN $openThreat AND t.severity IN ('CRITICAL', 'HIGH')) THEN 'high' WHEN $openThreat) THEN 'warning' ELSE 'safe' END
            WHERE id = ?")->execute([$data['hostname'], $data['ipAddress'], $data['macAddress'], $data['operatingSystem'], $data['agentVersion'], $data['cpuUsage'], $data['memoryUsage'], $data['diskUsage'], $computerId]);
    }

    /** @return array{0: int, 1: int} [accepted, duplicates]; events are already validated. Duplicate event UIDs (agent retries) are skipped. */
    public static function insertFileEvents(int $computerId, array $events): array
    {
        $db = self::db();
        $statement = $db->prepare('INSERT INTO file_events (event_uid, computer_id, event_type, file_name, file_path, file_size, sha256, detected_at, risk_level, suggested_confidential) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE id = id');
        $accepted = 0;
        $db->beginTransaction();
        try {
            foreach ($events as $event) { $created = $event['type'] === 'created'; $statement->execute([$event['uid'], $computerId, $event['type'], $event['fileName'], $event['filePath'], $event['fileSize'], $event['sha256'], $event['detectedAt'], $created ? FileRisk::preScanRisk($event['fileName']) : 'Unknown', $created && FileRisk::suggestConfidential($event['fileName'], $event['filePath']) ? 1 : 0]); $accepted += $statement->rowCount() === 1 ? 1 : 0; }
            $db->commit();
        } catch (Throwable $exception) { $db->rollBack(); throw $exception; }
        return [$accepted, count($events) - $accepted];
    }

    public static function setPassword(int $userId, string $password): void { self::db()->prepare('UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?')->execute([password_hash($password, PASSWORD_DEFAULT), $userId]); }

    public static function revokeAgent(int $computerId): void { self::db()->prepare("UPDATE computers SET agent_token_hash = NULL, agent_status = 'disconnected', status = 'offline' WHERE id = ?")->execute([$computerId]); }

    /** Creates the computer if needed and stores a new agent token hash. @return array{0: int, 1: bool, 2: bool} [computer id, created, replaced an existing token] */
    public static function registerAgent(string $deviceId, string $hostname, string $ipAddress, string $tokenHash): array
    {
        $existing = self::findComputerForAgent($deviceId);
        if ($existing) { self::db()->prepare('UPDATE computers SET agent_token_hash = ? WHERE id = ?')->execute([$tokenHash, $existing['id']]); return [(int)$existing['id'], false, !empty($existing['agentTokenHash'])]; }
        self::db()->prepare("INSERT INTO computers (device_id, hostname, ip_address, operating_system, status, threat_level, last_seen, agent_status, agent_token_hash) VALUES (?, ?, ?, 'Unknown', 'offline', 'unknown', 'Never', 'disconnected', ?)")->execute([$deviceId, $hostname, $ipAddress, $tokenHash]);
        return [(int)self::db()->lastInsertId(), true, false];
    }

    // ---- Detected files and on-PC scanning (Phase 11) ---------------------------------------------------

    public static function findFileEvent(int $id): ?array { return self::fetchOne(self::FILE_EVENT_SELECT . ' WHERE f.id = ?', [$id]); }
    public static function scansForFileEvent(int $id): array { return self::fetchAll(self::SCAN_SELECT . ' WHERE s.file_event_id = ? ORDER BY s.id DESC LIMIT 20', [$id]); }

    public static function updateFileEvent(int $id, ?string $classification, ?string $status): array
    {
        self::db()->prepare('UPDATE file_events SET classification = COALESCE(?, classification), status = COALESCE(?, status) WHERE id = ?')->execute([$classification, $status, $id]);
        return self::findFileEvent($id) ?? [];
    }

    // Creates a PENDING scan that the agent on that computer picks up (see scanJobs). Returns the scan id.
    public static function requestScan(array $fileEvent, int $userId): int
    {
        $db = self::db();
        $db->beginTransaction();
        try {
            $db->prepare("INSERT INTO scans (computer_id, scan_type, status, file_name, file_hash, file_path, file_event_id, threat_count, created_by) VALUES (?, 'File Scan', 'PENDING', ?, ?, ?, ?, 0, ?)")
                ->execute([$fileEvent['computerId'], $fileEvent['fileName'], $fileEvent['sha256'], $fileEvent['filePath'], $fileEvent['id'], $userId]);
            $scanId = (int)$db->lastInsertId();
            $db->prepare("UPDATE file_events SET status = 'Scan Requested', scan_id = ? WHERE id = ?")->execute([$scanId, $fileEvent['id']]);
            $db->commit();
        } catch (Throwable $exception) { $db->rollBack(); throw $exception; }
        return $scanId;
    }

    /** Pending scans for one computer; a job not answered within 5 minutes is handed out again. */
    public static function scanJobs(int $computerId, int $limit = 5): array
    {
        $statement = self::db()->prepare("SELECT s.id, s.file_path, s.file_name, s.file_hash FROM scans s WHERE s.computer_id = ? AND s.status = 'PENDING' AND s.file_path IS NOT NULL AND (s.started_at IS NULL OR s.started_at < NOW() - INTERVAL 5 MINUTE) ORDER BY s.id LIMIT " . max(1, $limit));
        $statement->execute([$computerId]);
        $jobs = $statement->fetchAll();
        if ($jobs) self::db()->prepare('UPDATE scans SET started_at = NOW() WHERE id IN (' . implode(',', array_fill(0, count($jobs), '?')) . ')')->execute(array_column($jobs, 'id'));
        return array_map(fn($job) => ['scanId' => (int)$job['id'], 'filePath' => $job['file_path'], 'fileName' => $job['file_name'], 'expectedSha256' => $job['file_hash']], $jobs);
    }

    public static function findPendingScan(int $scanId, int $computerId): ?array { return self::fetchOne("SELECT s.*, c.hostname AS computer_hostname FROM scans s JOIN computers c ON c.id = s.computer_id WHERE s.id = ? AND s.computer_id = ? AND s.status = 'PENDING'", [$scanId, $computerId]); }

    /** VirusTotal reputation of a hash, cached for 24 hours (lookups that failed are not cached). */
    public static function hashReputation(string $sha256): array
    {
        $sha256 = strtolower($sha256);
        $statement = self::db()->prepare('SELECT * FROM hash_reputation WHERE sha256 = ? AND checked_at > NOW() - INTERVAL 1 DAY');
        $statement->execute([$sha256]);
        if ($row = $statement->fetch()) {
            return ['status' => $row['status'], 'malicious' => (int)$row['malicious'], 'suspicious' => (int)$row['suspicious'], 'harmless' => (int)$row['harmless'], 'undetected' => (int)$row['undetected'], 'total' => (int)$row['total'], 'name' => $row['name'], 'link' => VirusTotal::link($sha256), 'cached' => true];
        }
        $result = VirusTotal::lookup($sha256);
        if (in_array($result['status'], ['found', 'not_found'], true)) {
            self::db()->prepare('INSERT INTO hash_reputation (sha256, status, malicious, suspicious, harmless, undetected, total, name, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE status = VALUES(status), malicious = VALUES(malicious), suspicious = VALUES(suspicious), harmless = VALUES(harmless), undetected = VALUES(undetected), total = VALUES(total), name = VALUES(name), checked_at = VALUES(checked_at)')
                ->execute([$sha256, $result['status'], $result['malicious'] ?? 0, $result['suspicious'] ?? 0, $result['harmless'] ?? 0, $result['undetected'] ?? 0, $result['total'] ?? 0, $result['name'] ?? null]);
        }
        return $result;
    }

    public static function blocklistMatch(?string $sha256): ?array
    {
        if ($sha256 === null) return null;
        $statement = self::db()->prepare('SELECT name, severity FROM hash_blocklist WHERE sha256 = ? LIMIT 1');
        $statement->execute([strtolower($sha256)]);
        return $statement->fetch() ?: null;
    }

    /**
     * Stores a finished scan: updates the scan and its file event, and records a threat for THREAT results.
     * @param ?array $verdict FileRisk::verdict() result, or null when the scan failed
     */
    public static function completeScan(array $scan, ?array $verdict, ?string $sha256, int $durationMs, ?string $error, ?array $reputation = null): array
    {
        $db = self::db();
        $status = $verdict['status'] ?? 'FAILED';
        $risk = $verdict['risk'] ?? 'Unknown';
        $details = json_encode(($verdict ? ['findings' => $verdict['findings']] : ['error' => $error]) + ($reputation ? ['virusTotal' => $reputation] : []), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $duration = number_format($durationMs / 1000, 1) . ' sec';
        $db->beginTransaction();
        try {
            $db->prepare('UPDATE scans SET status = ?, risk_level = ?, file_hash = COALESCE(?, file_hash), threat_count = ?, completed_at = NOW(), started_at = COALESCE(started_at, NOW()), duration = ?, scan_details = ? WHERE id = ?')
                ->execute([$status, $risk, $sha256, $verdict['threatCount'] ?? 0, $duration, $details, $scan['id']]);
            if ($scan['fileEventId'] !== null) $db->prepare('UPDATE file_events SET status = ?, risk_level = ? WHERE id = ? AND scan_id = ?')->execute([$verdict ? 'Scanned' : 'Scan Failed', $risk, $scan['fileEventId'], $scan['id']]);
            if ($status === 'THREAT') {
                $top = $verdict['top'];
                $severity = $risk === 'Critical' ? 'CRITICAL' : 'HIGH';
                $db->prepare("INSERT INTO threats (computer_id, threat_name, description, severity, status, source) VALUES (?, ?, ?, ?, 'Detected', 'File Scanner')")
                    ->execute([$scan['computerId'], FileRisk::cut($top['title'] . ': ' . $scan['fileName'], 160), FileRisk::cut($top['detail'] . ' | File: ' . $scan['filePath'] . ' | Scan #' . $scan['id'], 2000), $severity]);
                $db->prepare("UPDATE computers SET status = 'threat', threat_level = 'high' WHERE id = ?")->execute([$scan['computerId']]);
            }
            $db->commit();
        } catch (Throwable $exception) { $db->rollBack(); throw $exception; }
        return self::find('scans', (int)$scan['id']) ?? [];
    }

    public static function tableAccessible(string $table): bool { if (!in_array($table, ['users', 'computers', 'threats', 'scans', 'activity_logs', 'permissions', 'settings', 'file_events', 'hash_blocklist', 'hash_reputation'], true)) return false; self::db()->query("SELECT 1 FROM `$table` LIMIT 1")->fetchAll(); return true; }
}
