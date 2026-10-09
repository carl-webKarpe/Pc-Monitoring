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
    // Pre-Phase-13 results used Critical/Low; they are shown as High/Unknown in the five-level scale.
    private const RISK_CLASS = "CASE s.risk_level WHEN 'Critical' THEN 'High' WHEN 'Low' THEN 'Unknown' ELSE s.risk_level END";
    private const SCAN_FROM = ' FROM scans s LEFT JOIN computers c ON c.id = s.computer_id LEFT JOIN users u ON u.id = s.created_by LEFT JOIN file_events f ON f.id = s.file_event_id
        LEFT JOIN quarantine_items q ON q.id = (SELECT MAX(q2.id) FROM quarantine_items q2 WHERE q2.file_event_id = s.file_event_id)';
    private const SCAN_SELECT = 'SELECT s.*, ' . self::RISK_CLASS . ' AS risk_class, (s.stored_file IS NOT NULL) AS stored_copy, c.hostname AS computer_hostname, c.device_id AS computer_device_id, c.status AS computer_status,
        u.username AS created_by_username, f.event_type AS file_event_type, q.id AS quarantine_id, q.status AS quarantine_status, q.last_error AS quarantine_error' . self::SCAN_FROM;
    private const RESOURCES = ['computers' => [self::COMPUTER_SELECT, 'c'], 'threats' => [self::THREAT_SELECT, 't'], 'scans' => [self::SCAN_SELECT, 's']];
    private const FILTERABLE = ['threats' => ['severity', 'status', 'computer_id'], 'scans' => ['status', 'scan_type', 'computer_id'], 'file_events' => ['computer_id', 'event_type', 'status']];
    private const FILE_EVENT_SELECT = 'SELECT f.*, c.hostname AS computer_hostname, c.device_id AS computer_device_id, c.ip_address AS computer_ip_address, c.status AS computer_status,
        s.status AS scan_status, s.scan_state AS scan_state, s.completed_at AS scan_completed_at, s.scan_details AS scan_details, s.detection AS scan_detection, s.evidence_strength AS scan_evidence_strength,
        q.id AS quarantine_id, q.status AS quarantine_status, q.last_error AS quarantine_error
        FROM file_events f JOIN computers c ON c.id = f.computer_id LEFT JOIN scans s ON s.id = f.scan_id
        LEFT JOIN quarantine_items q ON q.id = (SELECT MAX(q2.id) FROM quarantine_items q2 WHERE q2.file_event_id = f.id)';

    private static array $permissionCache = [];

    private static function db(): PDO { return Database::connection(); }
    private static function map(array $row): array { foreach ($row as $key => $value) { $camel = preg_replace_callback('/_([a-z])/', fn($m) => strtoupper($m[1]), $key); if ($camel !== $key) { $row[$camel] = $value; unset($row[$key]); } } return $row; }
    private static function public(array $row): array { unset($row['passwordHash'], $row['agentTokenHash'], $row['storedFile']); if (array_key_exists('storedCopy', $row)) $row['storedCopy'] = (bool)$row['storedCopy']; return $row; }
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
        // Scan results on the five-level scale (pre-Phase-13 Critical/Low rows count as High/Unknown).
        $risk = self::RISK_CLASS;
        $scans = $db->query("SELECT COUNT(*) AS total, COALESCE(SUM(s.scan_state = 'Completed'), 0) AS completed, COALESCE(SUM(s.scan_state IN ('Pending', 'Scanning')), 0) AS in_progress,
            COALESCE(SUM(s.scan_state = 'Completed' AND $risk = 'Safe'), 0) AS safe, COALESCE(SUM(s.scan_state = 'Completed' AND $risk = 'Medium'), 0) AS medium, COALESCE(SUM(s.scan_state = 'Completed' AND $risk = 'High'), 0) AS high,
            COALESCE(SUM(s.scan_state = 'Completed' AND $risk = 'Unknown'), 0) AS unknown, COALESCE(SUM(s.scan_state = 'Failed'), 0) AS failed FROM scans s")->fetch();
        $files = $db->query("SELECT COUNT(*) AS total, COALESCE(SUM(detected_at > NOW() - INTERVAL 1 DAY), 0) AS last_day FROM file_events")->fetch();
        $quarantined = (int)$db->query("SELECT COUNT(*) FROM quarantine_items WHERE status IN ('Quarantined', 'Release Requested', 'Delete Requested')")->fetchColumn();
        // Detections per day for the last 14 days (High / Medium scan results and threat records).
        $trend = [];
        $today = new DateTimeImmutable((string)$db->query('SELECT CURDATE()')->fetchColumn()); // the database's date, like the rows it counts
        for ($day = 13; $day >= 0; $day--) { $date = $today->modify("-$day day")->format('Y-m-d'); $trend[$date] = ['date' => $date, 'scans' => 0, 'high' => 0, 'medium' => 0, 'threats' => 0]; }
        foreach ($db->query("SELECT DATE(s.completed_at) AS day, COUNT(*) AS scans, SUM($risk = 'High') AS high, SUM($risk = 'Medium') AS medium FROM scans s WHERE s.completed_at >= CURDATE() - INTERVAL 13 DAY GROUP BY DATE(s.completed_at)")->fetchAll() as $row) {
            if (isset($trend[$row['day']])) $trend[$row['day']] = ['scans' => (int)$row['scans'], 'high' => (int)$row['high'], 'medium' => (int)$row['medium']] + $trend[$row['day']];
        }
        foreach ($db->query('SELECT DATE(detected_at) AS day, COUNT(*) AS threats FROM threats WHERE detected_at >= CURDATE() - INTERVAL 13 DAY GROUP BY DATE(detected_at)')->fetchAll() as $row) {
            if (isset($trend[$row['day']])) $trend[$row['day']]['threats'] = (int)$row['threats'];
        }
        return [
            'totalComputers' => (int)$computers['total'], 'onlineComputers' => (int)$computers['online'], 'offlineComputers' => (int)$computers['offline'], 'warningComputers' => (int)$computers['warning'], 'threatComputers' => (int)$computers['threat'], 'agentConnectedComputers' => (int)$computers['agent_connected'],
            'totalThreats' => (int)$threats['total'], 'openThreats' => (int)$threats['open'], 'criticalThreats' => (int)$threats['critical'], 'openCriticalThreats' => (int)$threats['critical_open'], 'highThreats' => (int)$threats['high'], 'mediumThreats' => (int)$threats['medium'], 'lowThreats' => (int)$threats['low'], 'resolvedThreats' => (int)$threats['resolved'],
            'totalScans' => (int)$scans['total'], 'recentScans' => (int)$scans['total'], 'filesScanned' => (int)$scans['completed'], 'scansInProgress' => (int)$scans['in_progress'],
            'safeScans' => (int)$scans['safe'], 'mediumScans' => (int)$scans['medium'], 'highScans' => (int)$scans['high'], 'unknownScans' => (int)$scans['unknown'], 'failedScans' => (int)$scans['failed'],
            'threatScans' => (int)$scans['high'], 'warningScans' => (int)$scans['medium'],
            'fileEvents' => (int)$files['total'], 'fileEventsLastDay' => (int)$files['last_day'], 'quarantinedFiles' => $quarantined,
            'trend' => array_values($trend), 'generatedAt' => date('Y-m-d H:i:s'),
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

    /**
     * Stores validated agent events; duplicate event UIDs (agent retries) are skipped.
     * @return array{0: int, 1: int, 2: array} [accepted, duplicates, newly stored events (with their id)]
     */
    public static function insertFileEvents(int $computerId, array $events): array
    {
        $db = self::db();
        $statement = $db->prepare("INSERT INTO file_events (event_uid, computer_id, event_type, file_name, file_path, previous_path, file_size, sha256, detected_at, origin, download_url, risk_level, suggested_confidential) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Unknown', ?) ON DUPLICATE KEY UPDATE id = id");
        $stored = [];
        $db->beginTransaction();
        try {
            foreach ($events as $event) {
                $exists = $event['type'] !== 'deleted';
                $statement->execute([$event['uid'], $computerId, $event['type'], $event['fileName'], $event['filePath'], $event['previousPath'], $event['fileSize'], $event['sha256'], $event['detectedAt'], $event['origin'], $event['downloadUrl'], $exists && FileRisk::suggestConfidential($event['fileName'], $event['filePath']) ? 1 : 0]);
                if ($statement->rowCount() === 1) $stored[] = ['id' => (int)$db->lastInsertId(), 'computerId' => $computerId] + $event;
            }
            $db->commit();
        } catch (Throwable $exception) { $db->rollBack(); throw $exception; }
        return [count($stored), count($events) - count($stored), $stored];
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

    // ---- Detected files, scans and quarantine (Phase 11 + Phase 13) --------------------------------------

    public static function findFileEvent(int $id): ?array { return self::fetchOne(self::FILE_EVENT_SELECT . ' WHERE f.id = ?', [$id]); }
    public static function scansForFileEvent(int $id): array { return self::fetchAll(self::SCAN_SELECT . ' WHERE s.file_event_id = ? ORDER BY s.id DESC LIMIT 20', [$id]); }

    public static function updateFileEvent(int $id, ?string $classification, ?string $status): array
    {
        self::db()->prepare('UPDATE file_events SET classification = COALESCE(?, classification), status = COALESCE(?, status) WHERE id = ?')->execute([$classification, $status, $id]);
        return self::findFileEvent($id) ?? [];
    }

    // Creates a Pending scan that the agent on that computer picks up (see scanJobs). $userId is null for automatic scans.
    public static function requestScan(array $fileEvent, ?int $userId, string $source = 'Agent'): int
    {
        $db = self::db();
        $db->beginTransaction();
        try {
            $db->prepare("INSERT INTO scans (computer_id, scan_type, source, status, scan_state, file_name, file_hash, file_size, file_path, file_event_id, threat_count, created_by) VALUES (?, 'File Scan', ?, 'PENDING', 'Pending', ?, ?, ?, ?, ?, 0, ?)")
                ->execute([$fileEvent['computerId'], $source, $fileEvent['fileName'], $fileEvent['sha256'], $fileEvent['fileSize'], $fileEvent['filePath'], $fileEvent['id'], $userId]);
            $scanId = (int)$db->lastInsertId();
            $db->prepare("UPDATE file_events SET status = 'Scan Requested', scan_id = ? WHERE id = ?")->execute([$scanId, $fileEvent['id']]);
            $db->commit();
        } catch (Throwable $exception) { $db->rollBack(); throw $exception; }
        return $scanId;
    }

    public static function recentAutoScans(int $computerId, int $minutes): int { $statement = self::db()->prepare("SELECT COUNT(*) FROM scans WHERE computer_id = ? AND source = 'Auto' AND created_at > NOW() - INTERVAL ? MINUTE"); $statement->execute([$computerId, $minutes]); return (int)$statement->fetchColumn(); }

    /** Pending scans for one computer; a job not answered within 5 minutes is handed out again. */
    public static function scanJobs(int $computerId, int $limit = 5): array
    {
        $statement = self::db()->prepare("SELECT s.id, s.file_path, s.file_name, s.file_hash FROM scans s WHERE s.computer_id = ? AND s.status = 'PENDING' AND s.file_path IS NOT NULL AND (s.started_at IS NULL OR s.started_at < NOW() - INTERVAL 5 MINUTE) ORDER BY s.id LIMIT " . max(1, $limit));
        $statement->execute([$computerId]);
        $jobs = $statement->fetchAll();
        if ($jobs) self::db()->prepare("UPDATE scans SET started_at = NOW(), scan_state = 'Scanning' WHERE id IN (" . implode(',', array_fill(0, count($jobs), '?')) . ')')->execute(array_column($jobs, 'id'));
        return array_map(fn($job) => ['scanId' => (int)$job['id'], 'filePath' => $job['file_path'], 'fileName' => $job['file_name'], 'expectedSha256' => $job['file_hash']], $jobs);
    }

    public static function findPendingScan(int $scanId, int $computerId): ?array { return self::fetchOne("SELECT s.* FROM scans s WHERE s.id = ? AND s.computer_id = ? AND s.status = 'PENDING'", [$scanId, $computerId]); }

    /** An upload scan (on the MST server). */
    public static function createUploadScan(string $fileName, string $sha256, int $size, int $userId, ?string $storedFile, int $retentionDays): int
    {
        self::db()->prepare("INSERT INTO scans (computer_id, scan_type, source, status, scan_state, file_name, file_hash, file_size, threat_count, started_at, created_by, stored_file, stored_until) VALUES (NULL, 'File Scan', 'Upload', 'PENDING', 'Scanning', ?, ?, ?, 0, NOW(), ?, ?, NOW() + INTERVAL ? DAY)")
            ->execute([$fileName, $sha256, $size, $userId, $storedFile, $retentionDays]);
        return (int)self::db()->lastInsertId();
    }

    /** Raw row including the stored file name (never returned to clients). */
    public static function scanRow(int $id): ?array { $statement = self::db()->prepare('SELECT * FROM scans WHERE id = ?'); $statement->execute([$id]); $row = $statement->fetch(); return $row ? self::map($row) : null; }
    public static function moveStoredFile(int $fromScanId, int $toScanId): void
    {
        self::db()->prepare('UPDATE scans t JOIN scans f ON f.id = ? SET t.stored_file = f.stored_file, t.stored_until = f.stored_until WHERE t.id = ?')->execute([$fromScanId, $toScanId]);
        self::db()->prepare('UPDATE scans SET stored_file = NULL, stored_until = NULL WHERE id = ?')->execute([$fromScanId]);
    }
    public static function clearStoredFile(int $scanId): void { self::db()->prepare('UPDATE scans SET stored_file = NULL, stored_until = NULL WHERE id = ?')->execute([$scanId]); }
    /** @return array<int, array{id: int, storedFile: string}> uploaded copies whose retention period is over */
    public static function expiredStoredFiles(): array { return array_map(fn($row) => ['id' => (int)$row['id'], 'storedFile' => $row['stored_file']], self::db()->query('SELECT id, stored_file FROM scans WHERE stored_file IS NOT NULL AND stored_until < NOW() LIMIT 200')->fetchAll()); }

    /** A completed scan of the same content in the last 24 hours (duplicate upload detection). */
    public static function recentScanOfHash(string $sha256): ?array { return self::fetchOne(self::SCAN_SELECT . " WHERE s.file_hash = ? AND s.scan_state = 'Completed' AND s.completed_at > NOW() - INTERVAL 1 DAY ORDER BY s.id DESC LIMIT 1", [strtolower($sha256)]); }
    public static function scansOfHash(string $sha256, int $exceptId): array { return self::fetchAll(self::SCAN_SELECT . ' WHERE s.file_hash = ? AND s.id <> ? ORDER BY s.id DESC LIMIT 20', [strtolower($sha256), $exceptId]); }

    /** Upload scans still waiting for VirusTotal's analysis, oldest check first. */
    public static function scansWaitingForVirusTotal(int $limit): array
    {
        return array_map(fn($row) => self::map($row), self::db()->query("SELECT * FROM scans WHERE scan_state = 'Scanning' AND vt_analysis_id IS NOT NULL AND (vt_checked_at IS NULL OR vt_checked_at < NOW() - INTERVAL 15 SECOND) ORDER BY vt_checked_at IS NOT NULL, vt_checked_at LIMIT " . max(1, $limit))->fetchAll());
    }
    public static function markVirusTotalChecked(int $scanId, ?string $analysisId = null): void { self::db()->prepare('UPDATE scans SET vt_checked_at = NOW(), vt_analysis_id = COALESCE(?, vt_analysis_id) WHERE id = ?')->execute([$analysisId, $scanId]); }

    /** Scan History: search, filters, sorting and paging. @return array{0: array, 1: int} [rows, total matching rows] */
    public static function searchScans(array $filters, string $sort, string $direction, int $limit, int $offset): array
    {
        $where = []; $params = [];
        if (($filters['q'] ?? '') !== '') {
            $like = '%' . addcslashes($filters['q'], '%_\\') . '%';
            $id = preg_match('/^(?:SCN-)?0*(\d{1,9})$/i', $filters['q'], $match) ? (int)$match[1] : 0;
            $where[] = '(s.file_name LIKE ? OR s.file_hash LIKE ? OR c.hostname LIKE ? OR c.device_id LIKE ? OR s.id = ?)';
            array_push($params, $like, $like, $like, $like, $id);
        }
        if (isset($filters['risk'])) { $where[] = self::RISK_CLASS . ' = ?'; $params[] = $filters['risk']; }
        if (isset($filters['state'])) { $where[] = 's.scan_state = ?'; $params[] = $filters['state']; }
        if (isset($filters['source'])) { $where[] = 's.source = ?'; $params[] = $filters['source']; }
        if (isset($filters['computerId'])) { $where[] = 's.computer_id = ?'; $params[] = $filters['computerId']; }
        if (isset($filters['from'])) { $where[] = 'COALESCE(s.completed_at, s.created_at) >= ?'; $params[] = $filters['from'] . ' 00:00:00'; }
        if (isset($filters['to'])) { $where[] = 'COALESCE(s.completed_at, s.created_at) < ? + INTERVAL 1 DAY'; $params[] = $filters['to'] . ' 00:00:00'; }
        $condition = $where ? ' WHERE ' . implode(' AND ', $where) : '';
        $order = [
            'id' => 's.id', 'file' => 's.file_name', 'computer' => 'c.hostname', 'state' => 's.scan_state', 'date' => 'COALESCE(s.completed_at, s.created_at)',
            'risk' => "FIELD(" . self::RISK_CLASS . ", 'Safe', 'Unknown', 'Failed', 'Medium', 'High')",
        ][$sort] ?? 's.id';
        $direction = $direction === 'asc' ? 'ASC' : 'DESC';
        $count = self::db()->prepare('SELECT COUNT(*)' . self::SCAN_FROM . $condition);
        $count->execute($params);
        $rows = self::fetchAll(self::SCAN_SELECT . $condition . " ORDER BY $order $direction, s.id $direction LIMIT " . max(1, $limit) . ' OFFSET ' . max(0, $offset), $params);
        return [$rows, (int)$count->fetchColumn()];
    }

    /** VirusTotal reputation of a hash, cached for 24 hours (lookups that failed are not cached). */
    public static function hashReputation(string $sha256): array
    {
        $sha256 = strtolower($sha256);
        $statement = self::db()->prepare('SELECT * FROM hash_reputation WHERE sha256 = ? AND checked_at > NOW() - INTERVAL 1 DAY');
        $statement->execute([$sha256]);
        if ($row = $statement->fetch()) {
            return ['status' => $row['status'], 'malicious' => (int)$row['malicious'], 'suspicious' => (int)$row['suspicious'], 'harmless' => (int)$row['harmless'], 'undetected' => (int)$row['undetected'], 'total' => (int)$row['total'], 'name' => $row['name'], 'link' => VirusTotal::link($sha256), 'cached' => true, 'checkedAt' => $row['checked_at']];
        }
        $result = VirusTotal::lookup($sha256);
        if (in_array($result['status'], ['found', 'not_found'], true)) self::saveReputation($sha256, $result);
        return $result + ['checkedAt' => date('Y-m-d H:i:s')];
    }

    public static function saveReputation(string $sha256, array $result): void
    {
        self::db()->prepare('INSERT INTO hash_reputation (sha256, status, malicious, suspicious, harmless, undetected, total, name, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE status = VALUES(status), malicious = VALUES(malicious), suspicious = VALUES(suspicious), harmless = VALUES(harmless), undetected = VALUES(undetected), total = VALUES(total), name = VALUES(name), checked_at = VALUES(checked_at)')
            ->execute([strtolower($sha256), $result['status'], $result['malicious'] ?? 0, $result['suspicious'] ?? 0, $result['harmless'] ?? 0, $result['undetected'] ?? 0, $result['total'] ?? 0, $result['name'] ?? null]);
    }

    public static function blocklistMatch(?string $sha256): ?array
    {
        if ($sha256 === null) return null;
        $statement = self::db()->prepare('SELECT name, severity FROM hash_blocklist WHERE sha256 = ? LIMIT 1');
        $statement->execute([strtolower($sha256)]);
        return $statement->fetch() ?: null;
    }

    /**
     * Stores a scan result. $final = false keeps the scan "Scanning" (an uploaded file is still being analysed by
     * VirusTotal): the evidence so far is saved, but the file and threat records are only updated when it is final.
     * @param array $classification ScanClassifier::classify() result
     */
    public static function completeScan(array $scan, array $evidence, array $classification, ?string $sha256, ?int $fileSize, int $durationMs, bool $final = true): array
    {
        $db = self::db();
        $risk = $classification['risk'];
        $state = !$final ? 'Scanning' : ($risk === 'Failed' ? 'Failed' : 'Completed');
        $details = json_encode($evidence + ['factors' => $classification['factors'], 'recommendations' => $classification['recommendations']], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        $db->beginTransaction();
        try {
            $db->prepare('UPDATE scans SET status = ?, scan_state = ?, risk_level = ?, detection = ?, evidence_strength = ?, analysis_coverage = ?, scanner = ?, file_hash = COALESCE(?, file_hash), file_size = COALESCE(?, file_size), file_type = ?, threat_count = ?,
                completed_at = ' . ($final ? 'NOW()' : 'NULL') . ', started_at = COALESCE(started_at, NOW()), duration = ?, scan_details = ? WHERE id = ?')
                ->execute([$final ? $classification['status'] : 'PENDING', $state, $risk, $classification['detection'], $classification['strength'], $classification['coverage'], $classification['scanner'], $sha256, $fileSize,
                    isset($evidence['fileType']['label']) ? FileRisk::cut($evidence['fileType']['label'], 80) : null, $classification['threatCount'], number_format($durationMs / 1000, 1) . ' sec', $details, $scan['id']]);
            if ($final && ($scan['fileEventId'] ?? null) !== null) $db->prepare('UPDATE file_events SET status = ?, risk_level = ? WHERE id = ? AND scan_id = ?')->execute([$risk === 'Failed' ? 'Scan Failed' : 'Scanned', $risk, $scan['fileEventId'], $scan['id']]);
            if ($final && $risk === 'High') {
                $where = $scan['filePath'] ?? null ? ' | File: ' . $scan['filePath'] : ' | Uploaded on the File Scanner page';
                $db->prepare("INSERT INTO threats (computer_id, scan_id, threat_name, description, severity, status, source) VALUES (?, ?, ?, ?, ?, 'Detected', ?)")
                    ->execute([$scan['computerId'], $scan['id'], FileRisk::cut($classification['detection'], 120) . ' (' . FileRisk::cut((string)$scan['fileName'], 36) . ')', FileRisk::cut($classification['detection'] . $where . ' | Scan #' . $scan['id'], 2000), $classification['threatSeverity'], $scan['source'] === 'Upload' ? 'File Scanner (upload)' : 'File Scanner']);
                if ($scan['computerId'] !== null) $db->prepare("UPDATE computers SET status = 'threat', threat_level = 'high' WHERE id = ?")->execute([$scan['computerId']]);
            }
            $db->commit();
        } catch (Throwable $exception) { $db->rollBack(); throw $exception; }
        return self::find('scans', (int)$scan['id']) ?? [];
    }

    public static function threatForScan(int $scanId): ?array { return self::fetchOne(self::THREAT_SELECT . ' WHERE t.scan_id = ? ORDER BY t.id DESC LIMIT 1', [$scanId]); }
    public static function recentFileEventsForComputer(int $computerId, string $around): array { return self::fetchAll(self::FILE_EVENT_SELECT . ' WHERE f.computer_id = ? AND f.detected_at BETWEEN ? - INTERVAL 1 HOUR AND ? + INTERVAL 1 HOUR ORDER BY f.detected_at DESC LIMIT 15', [$computerId, $around, $around]); }

    // ---- Quarantine (Phase 13) -------------------------------------------------------------------------

    private const QUARANTINE_SELECT = "SELECT q.*, c.hostname AS computer_hostname, c.device_id AS computer_device_id, c.status AS computer_status, u.username AS requested_by_username,
        (SELECT CASE s.risk_level WHEN 'Critical' THEN 'High' WHEN 'Low' THEN 'Unknown' ELSE s.risk_level END FROM scans s WHERE s.file_event_id = q.file_event_id AND s.scan_state IN ('Completed', 'Failed') ORDER BY s.id DESC LIMIT 1) AS latest_risk
        FROM quarantine_items q JOIN computers c ON c.id = q.computer_id LEFT JOIN users u ON u.id = q.requested_by";
    public const QUARANTINE_ACTIVE = ['Quarantine Requested', 'Quarantined', 'Release Requested', 'Delete Requested'];

    public static function findQuarantine(int $id): ?array { return self::fetchOne(self::QUARANTINE_SELECT . ' WHERE q.id = ?', [$id]); }
    public static function listQuarantine(int $limit, int $offset): array { return self::fetchAll(self::QUARANTINE_SELECT . ' ORDER BY q.id DESC LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset)); }
    public static function activeQuarantineForFile(int $fileEventId): ?array { return self::fetchOne(self::QUARANTINE_SELECT . " WHERE q.file_event_id = ? AND q.status IN ('" . implode("', '", self::QUARANTINE_ACTIVE) . "') ORDER BY q.id DESC LIMIT 1", [$fileEventId]); }

    public static function createQuarantine(array $fileEvent, ?int $scanId, string $sha256, int $userId): int
    {
        self::db()->prepare("INSERT INTO quarantine_items (computer_id, file_event_id, scan_id, file_name, original_path, sha256, status, pending_action, requested_by) VALUES (?, ?, ?, ?, ?, ?, 'Quarantine Requested', 'quarantine', ?)")
            ->execute([$fileEvent['computerId'], $fileEvent['id'], $scanId, $fileEvent['fileName'], $fileEvent['filePath'], strtolower($sha256), $userId]);
        return (int)self::db()->lastInsertId();
    }

    public static function requestQuarantineAction(int $id, string $action, string $status, int $userId, ?string $reason = null): void
    {
        self::db()->prepare("UPDATE quarantine_items SET pending_action = ?, status = ?, action_sent_at = NULL, last_error = NULL, requested_by = ?, release_reason = COALESCE(?, release_reason) WHERE id = ? AND status = 'Quarantined'")->execute([$action, $status, $userId, $reason, $id]);
    }

    /** Quarantine/release/delete jobs for one computer's agent; an unanswered job is handed out again after 5 minutes. */
    public static function quarantineJobs(int $computerId, int $limit = 5): array
    {
        $statement = self::db()->prepare('SELECT id, pending_action, original_path, sha256, quarantine_name FROM quarantine_items WHERE computer_id = ? AND pending_action IS NOT NULL AND (action_sent_at IS NULL OR action_sent_at < NOW() - INTERVAL 5 MINUTE) ORDER BY id LIMIT ' . max(1, $limit));
        $statement->execute([$computerId]);
        $jobs = $statement->fetchAll();
        if ($jobs) self::db()->prepare('UPDATE quarantine_items SET action_sent_at = NOW() WHERE id IN (' . implode(',', array_fill(0, count($jobs), '?')) . ')')->execute(array_column($jobs, 'id'));
        return array_map(fn($job) => ['itemId' => (int)$job['id'], 'action' => $job['pending_action'], 'originalPath' => $job['original_path'], 'sha256' => $job['sha256'], 'quarantineName' => $job['quarantine_name']], $jobs);
    }

    public static function pendingQuarantineItem(int $id, int $computerId, string $action): ?array { return self::fetchOne('SELECT q.* FROM quarantine_items q WHERE q.id = ? AND q.computer_id = ? AND q.pending_action = ?', [$id, $computerId, $action]); }

    /** Applies the agent's answer to a quarantine job and keeps the related threat in step. */
    public static function finishQuarantineAction(array $item, string $action, bool $succeeded, ?string $quarantineName, ?string $error): array
    {
        $db = self::db();
        $db->beginTransaction();
        try {
            if (!$succeeded) {
                $status = $action === 'quarantine' ? 'Failed' : 'Quarantined';
                $db->prepare('UPDATE quarantine_items SET status = ?, pending_action = NULL, last_error = ? WHERE id = ?')->execute([$status, $error, $item['id']]);
            } else {
                [$status, $column] = ['quarantine' => ['Quarantined', 'quarantined_at'], 'release' => ['Released', 'released_at'], 'delete' => ['Deleted', 'deleted_at']][$action];
                $db->prepare("UPDATE quarantine_items SET status = ?, pending_action = NULL, last_error = NULL, $column = NOW(), quarantine_name = COALESCE(?, quarantine_name) WHERE id = ?")->execute([$status, $quarantineName, $item['id']]);
                $threatStatus = ['quarantine' => 'Quarantined', 'delete' => 'Resolved'][$action] ?? null;
                if ($threatStatus !== null && $item['fileEventId'] !== null) {
                    $db->prepare("UPDATE threats SET status = ?, resolved_at = CASE WHEN ? = 'Resolved' THEN NOW() ELSE resolved_at END WHERE scan_id IN (SELECT id FROM scans WHERE file_event_id = ?) AND status NOT IN ('Resolved', 'Ignored')")->execute([$threatStatus, $threatStatus, $item['fileEventId']]);
                }
            }
            $db->commit();
        } catch (Throwable $exception) { $db->rollBack(); throw $exception; }
        return self::findQuarantine((int)$item['id']) ?? [];
    }

    public static function tableAccessible(string $table): bool { if (!in_array($table, ['users', 'computers', 'threats', 'scans', 'activity_logs', 'permissions', 'settings', 'file_events', 'hash_blocklist', 'hash_reputation', 'quarantine_items'], true)) return false; self::db()->query("SELECT 1 FROM `$table` LIMIT 1")->fetchAll(); return true; }
}
