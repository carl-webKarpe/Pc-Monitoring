<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/Database.php';

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
    private const FILTERABLE = ['threats' => ['severity', 'status', 'computer_id'], 'scans' => ['status', 'scan_type', 'computer_id']];

    private static array $permissionCache = [];

    private static function db(): PDO { return Database::connection(); }
    private static function map(array $row): array { foreach ($row as $key => $value) { $camel = preg_replace_callback('/_([a-z])/', fn($m) => strtoupper($m[1]), $key); if ($camel !== $key) { $row[$camel] = $value; unset($row[$key]); } } return $row; }
    private static function public(array $row): array { unset($row['passwordHash']); return $row; }
    private static function roleClause(array $roles): string { return 'role IN (' . implode(', ', array_fill(0, count($roles), '?')) . ')'; }
    private static function optionalText(array $data, string $field): ?string { return isset($data[$field]) && trim((string)$data[$field]) !== '' ? trim((string)$data[$field]) : null; }
    private static function fetchAll(string $sql, array $params = []): array { $statement = self::db()->prepare($sql); $statement->execute($params); return array_map(fn($row) => self::public(self::map($row)), $statement->fetchAll()); }
    private static function fetchOne(string $sql, array $params): ?array { $statement = self::db()->prepare($sql); $statement->execute($params); $row = $statement->fetch(); return $row ? self::public(self::map($row)) : null; }

    public static function list(string $resource, array $filters = [], int $limit = 500, int $offset = 0): array
    {
        $page = ' LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset);
        if (isset(self::ACCOUNT_ROLES[$resource])) { $roles = self::ACCOUNT_ROLES[$resource]; return self::fetchAll('SELECT * FROM users WHERE ' . self::roleClause($roles) . ' ORDER BY id DESC' . $page, $roles); }
        if (!isset(self::RESOURCES[$resource])) throw new InvalidArgumentException('Unsupported resource');
        [$select, $alias] = self::RESOURCES[$resource];
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

    public static function settings(): array { $result = []; foreach (self::db()->query('SELECT setting_key, setting_value FROM settings')->fetchAll() as $row) $result[$row['setting_key']] = $row['setting_value']; return $result; }
    public static function saveSettings(array $settings): array { $statement = self::db()->prepare('INSERT INTO settings (category, setting_key, setting_value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = CURRENT_TIMESTAMP'); foreach ($settings as $key => [$category, $value]) $statement->execute([$category, $key, $value]); return self::settings(); }

    public static function tableAccessible(string $table): bool { if (!in_array($table, ['users', 'computers', 'threats', 'scans', 'activity_logs', 'permissions', 'settings'], true)) return false; self::db()->query("SELECT 1 FROM `$table` LIMIT 1")->fetchAll(); return true; }
}
