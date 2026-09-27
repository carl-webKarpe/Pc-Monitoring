<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/Database.php';

final class MySQLRepository
{
    // Tenants are managed through /users and administrators through /admins; each endpoint only sees its own roles.
    private const ACCOUNT_ROLES = ['users' => ['Tenant'], 'admins' => ['Admin', 'Super Admin']];
    private const REMOVABLE_ROLES = ['users' => ['Tenant'], 'admins' => ['Admin']];
    private static function db(): PDO { return Database::connection(); }
    private static function roleClause(array $roles): string { return 'role IN (' . implode(', ', array_fill(0, count($roles), '?')) . ')'; }
    private static function accounts(string $resource): array { $roles = self::ACCOUNT_ROLES[$resource]; $statement = self::db()->prepare('SELECT * FROM users WHERE ' . self::roleClause($roles) . ' ORDER BY id DESC'); $statement->execute($roles); return array_map(fn($row) => self::public(self::map($row)), $statement->fetchAll()); }
    private static function optionalText(array $data, string $field): ?string { return isset($data[$field]) && trim((string)$data[$field]) !== '' ? trim((string)$data[$field]) : null; }
    private static function map(array $row): array { foreach ($row as $key => $value) { $camel = preg_replace_callback('/_([a-z])/', fn($m) => strtoupper($m[1]), $key); if ($camel !== $key) { $row[$camel] = $value; unset($row[$key]); } } return $row; }
    private static function public(array $row): array { unset($row['passwordHash']); return $row; }
    private static function rows(string $table): array { return array_map(fn($row) => self::public(self::map($row)), self::db()->query("SELECT * FROM `$table` ORDER BY id DESC")->fetchAll()); }
    public static function users(): array { return self::accounts('users'); }
    public static function admins(): array { return self::accounts('admins'); }
    public static function find(string $resource, int $id): ?array
    {
        if (isset(self::ACCOUNT_ROLES[$resource])) { $roles = self::ACCOUNT_ROLES[$resource]; $statement = self::db()->prepare('SELECT * FROM users WHERE id = ? AND ' . self::roleClause($roles)); $statement->execute([$id, ...$roles]); }
        else { if (!in_array($resource, ['computers', 'threats', 'scans'], true)) return null; $statement = self::db()->prepare("SELECT * FROM `$resource` WHERE id = ?"); $statement->execute([$id]); }
        $row = $statement->fetch();
        return $row ? self::public(self::map($row)) : null;
    }
    public static function resource(string $resource): array { return match ($resource) { 'users' => self::users(), 'admins' => self::admins(), 'computers' => self::rows('computers'), 'threats' => self::rows('threats'), 'scans' => self::rows('scans'), default => [] }; }
    public static function findByUsername(string $username): ?array { $statement = self::db()->prepare('SELECT * FROM users WHERE username = ? LIMIT 1'); $statement->execute([$username]); $row = $statement->fetch(); return $row ? self::map($row) : null; }
    public static function touchLogin(int $id): void { self::db()->prepare('UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = ?')->execute([$id]); }
    public static function create(string $resource, array $data): array { if (!isset(self::ACCOUNT_ROLES[$resource])) throw new InvalidArgumentException('Unsupported resource'); $statement = self::db()->prepare('INSERT INTO users (first_name, middle_name, last_name, email, username, password_hash, role, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'); $statement->execute([trim((string)$data['firstName']), self::optionalText($data, 'middleName'), trim((string)$data['lastName']), trim((string)$data['email']), trim((string)$data['username']), password_hash((string)$data['password'], PASSWORD_DEFAULT), $resource === 'admins' ? 'Admin' : 'Tenant', $data['status'] ?? 'Active']); return self::find($resource, (int)self::db()->lastInsertId()) ?? []; }
    public static function update(string $resource, int $id, array $data): array { if (!isset(self::ACCOUNT_ROLES[$resource])) throw new InvalidArgumentException('Unsupported resource'); $roles = self::ACCOUNT_ROLES[$resource]; $statement = self::db()->prepare('UPDATE users SET first_name = COALESCE(?, first_name), middle_name = COALESCE(?, middle_name), last_name = COALESCE(?, last_name), email = COALESCE(?, email), username = COALESCE(?, username), status = COALESCE(?, status), updated_at = NOW() WHERE id = ? AND ' . self::roleClause($roles)); $statement->execute([self::optionalText($data, 'firstName'), self::optionalText($data, 'middleName'), self::optionalText($data, 'lastName'), self::optionalText($data, 'email'), self::optionalText($data, 'username'), $data['status'] ?? null, $id, ...$roles]); return self::find($resource, $id) ?? []; }
    public static function updateThreatStatus(int $id, string $status): array { $statement = self::db()->prepare('UPDATE threats SET status = ?, resolved_at = CASE WHEN ? = ? THEN CURRENT_TIMESTAMP ELSE resolved_at END, updated_at = NOW() WHERE id = ?'); $statement->execute([$status, $status, 'Resolved', $id]); return self::find('threats', $id) ?? []; }
    public static function delete(string $resource, int $id): bool { $roles = self::REMOVABLE_ROLES[$resource] ?? null; if ($roles === null) throw new InvalidArgumentException('Unsupported resource'); $statement = self::db()->prepare('DELETE FROM users WHERE id = ? AND ' . self::roleClause($roles)); $statement->execute([$id, ...$roles]); return $statement->rowCount() > 0; }
    public static function reports(): array { $db = self::db(); return ['totalComputers' => (int)$db->query('SELECT COUNT(*) FROM computers')->fetchColumn(), 'onlineComputers' => (int)$db->query("SELECT COUNT(*) FROM computers WHERE status = 'online'")->fetchColumn(), 'offlineComputers' => (int)$db->query("SELECT COUNT(*) FROM computers WHERE status = 'offline'")->fetchColumn(), 'totalThreats' => (int)$db->query('SELECT COUNT(*) FROM threats')->fetchColumn(), 'criticalThreats' => (int)$db->query("SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL'")->fetchColumn(), 'highThreats' => (int)$db->query("SELECT COUNT(*) FROM threats WHERE severity = 'HIGH'")->fetchColumn(), 'recentScans' => (int)$db->query('SELECT COUNT(*) FROM scans')->fetchColumn(), 'resolvedThreats' => (int)$db->query("SELECT COUNT(*) FROM threats WHERE status = 'Resolved'")->fetchColumn()]; }
    public static function activity(): array { return self::rows('activity_logs'); }
    public static function log(int $userId, string $action, string $description = ''): void { self::db()->prepare('INSERT INTO activity_logs (user_id, action, description) VALUES (?, ?, ?)')->execute([$userId, $action, $description]); }
    public static function permissions(): array { $rows = self::rows('permissions'); $result = []; foreach ($rows as $row) { $result[$row['role']][$row['module']] = (bool)$row['allowed']; } return $result; }
    public static function settings(): array { $result = []; foreach (self::db()->query('SELECT setting_key, setting_value FROM settings')->fetchAll() as $row) $result[$row['setting_key']] = $row['setting_value']; return $result; }
    public static function saveSettings(array $data): array { $statement = self::db()->prepare('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = CURRENT_TIMESTAMP'); foreach ($data as $key => $value) { if (!is_scalar($value)) continue; $statement->execute([(string)$key, is_bool($value) ? ($value ? '1' : '0') : (string)$value]); } return self::settings(); }
    public static function savePermissions(string $role, array $permissions): array { $statement = self::db()->prepare('INSERT INTO permissions (role, module, allowed) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE allowed = VALUES(allowed)'); foreach ($permissions as $module => $allowed) $statement->execute([$role, (string)$module, (bool)$allowed ? 1 : 0]); return self::permissions(); }
}
