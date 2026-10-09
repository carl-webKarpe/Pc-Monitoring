<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';

// Files isolated on lab PCs. Viewing: Super Admin + Admin (Computer Monitoring). Release/delete: Admin (File Scanner).
final class QuarantineController
{
    private const MIN_REASON_LENGTH = 10;

    public static function index(string $method, ?string $id = null, ?string $action = null): never
    {
        if ($method === 'GET' && $id === null) self::list();
        if ($method === 'GET' && $id !== null && $action === null) self::show($id);
        if ($method === 'POST' && $id !== null && $action === 'release') self::release($id);
        if ($method === 'POST' && $id !== null && $action === 'delete') self::delete($id);
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    private static function list(): never
    {
        RoleMiddleware::allowModule('computer_monitoring');
        [$limit, $offset] = Validation::page(100, 500);
        Response::success('Request successful', MySQLRepository::listQuarantine($limit, $offset));
    }

    private static function findOrFail(string $id): array
    {
        $item = MySQLRepository::findQuarantine(Validation::id($id));
        if (!$item) Response::error('Quarantine record not found', 'NOT_FOUND', 404);
        return $item;
    }

    private static function show(string $id): never { RoleMiddleware::allowModule('computer_monitoring'); Response::success('Request successful', self::findOrFail($id)); }

    // Security check: a file whose latest scan is High risk cannot be released, and every release needs a written reason.
    private static function release(string $id): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        $item = self::findOrFail($id);
        $data = Validation::body();
        $reason = is_string($data['reason'] ?? null) ? trim(preg_replace('/[\x00-\x1F\x7F<>]/u', ' ', $data['reason']) ?? '') : '';
        if ($item['status'] !== 'Quarantined') Response::error('Only files that are in quarantine can be released', 'NOT_QUARANTINED', 409);
        if ($item['latestRisk'] === 'High') Response::error('The latest scan of this file is High risk, so it cannot be released. Delete it, or scan it again after the investigation.', 'RELEASE_BLOCKED', 409);
        if (!preg_match('/^.{' . self::MIN_REASON_LENGTH . ',255}$/us', $reason)) Validation::fail(['reason' => 'Explain why the file is safe to release (10-255 characters)']);
        if (($data['confirm'] ?? null) !== 'RELEASE') Validation::fail(['confirm' => 'Type RELEASE to confirm']);
        MySQLRepository::requestQuarantineAction((int)$item['id'], 'release', 'Release Requested', (int)$user['id'], $reason);
        MySQLRepository::log((int)$user['id'], 'QUARANTINE_RELEASE_REQUESTED', "Requested release of {$item['fileName']} on {$item['computerHostname']} (latest risk: " . ($item['latestRisk'] ?? 'not scanned') . "). Reason: $reason", 'quarantine', (string)$item['id']);
        Response::success('Release requested. The agent will restore the file to its original folder.', MySQLRepository::findQuarantine((int)$item['id']));
    }

    // Retention policy: files on lab PCs are only deleted permanently after they have been quarantined.
    private static function delete(string $id): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        $item = self::findOrFail($id);
        if ($item['status'] !== 'Quarantined') Response::error('Only files that are in quarantine can be deleted', 'NOT_QUARANTINED', 409);
        if ((Validation::body()['confirm'] ?? null) !== 'DELETE') Validation::fail(['confirm' => 'Type DELETE to confirm']);
        MySQLRepository::requestQuarantineAction((int)$item['id'], 'delete', 'Delete Requested', (int)$user['id']);
        MySQLRepository::log((int)$user['id'], 'QUARANTINE_DELETE_REQUESTED', "Requested permanent deletion of quarantined {$item['fileName']} on {$item['computerHostname']}", 'quarantine', (string)$item['id']);
        Response::success('Deletion requested. The agent will delete the quarantined file permanently.', MySQLRepository::findQuarantine((int)$item['id']));
    }
}
