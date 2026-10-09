<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';
require_once __DIR__ . '/../helpers/FileRisk.php';

// Files reported by the lab-PC agents: review, classification and on-PC scan requests.
final class FileEventController
{
    public static function index(string $method, ?string $id = null, ?string $action = null): never
    {
        if ($id === null && $method === 'GET') self::list();
        if ($id !== null && $action === null && $method === 'GET') self::show($id);
        if ($id !== null && $action === null && $method === 'PUT') self::update($id);
        if ($id !== null && $action === 'scan' && $method === 'POST') self::requestScan($id);
        if ($id !== null && $action === 'quarantine' && $method === 'POST') self::quarantineFile(Validation::id($id));
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    private static function list(): never
    {
        RoleMiddleware::allowModule('computer_monitoring');
        $filters = Validation::filters(['computerId' => ['computer_id', 'id'], 'type' => ['event_type', ['created', 'modified', 'renamed', 'deleted']], 'status' => ['status', ['New', 'Reviewed', 'Scan Requested', 'Scanned', 'Scan Failed']]]);
        [$limit, $offset] = Validation::page(100, 500);
        Response::success('Request successful', MySQLRepository::list('file_events', $filters, $limit, $offset));
    }

    private static function findOrFail(string $id): array
    {
        $event = MySQLRepository::findFileEvent(Validation::id($id));
        if (!$event) Response::error('File not found', 'NOT_FOUND', 404);
        return $event;
    }

    private static function show(string $id): never
    {
        RoleMiddleware::allowModule('computer_monitoring');
        $event = self::findOrFail($id);
        $event['scans'] = MySQLRepository::scansForFileEvent((int)$event['id']);
        Response::success('Request successful', $event);
    }

    private static function update(string $id): never
    {
        $user = RoleMiddleware::allowModule('computer_monitoring');
        $event = self::findOrFail($id);
        $data = Validation::body();
        $classification = $data['classification'] ?? null;
        $status = $data['status'] ?? null;
        $errors = [];
        if ($classification !== null && !in_array($classification, FileRisk::CLASSIFICATIONS, true)) $errors['classification'] = 'classification must be Normal or Confidential';
        if ($status !== null && $status !== 'Reviewed') $errors['status'] = 'status can only be set to Reviewed';
        if ($status === 'Reviewed' && $event['status'] !== 'New') $errors['status'] = 'Only new files can be marked as reviewed';
        if ($classification === null && $status === null) $errors['file'] = 'Nothing to update';
        if ($errors !== []) Validation::fail($errors);
        $updated = MySQLRepository::updateFileEvent((int)$event['id'], $classification, $status);
        $changes = array_filter([$classification !== null ? "classified as $classification" : null, $status !== null ? 'marked reviewed' : null]);
        MySQLRepository::log((int)$user['id'], 'FILE_UPDATED', "{$event['fileName']} on {$event['computerHostname']}: " . implode(', ', $changes), 'file_event', (string)$event['id']);
        Response::success('File updated', $updated);
    }

    // Scanning belongs to the File Scanner module (Admin only, per the MST role rules).
    private static function requestScan(string $id): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        $event = self::findOrFail($id);
        if ($event['eventType'] === 'deleted') Response::error('Only files that still exist can be scanned', 'FILE_DELETED', 409);
        if (in_array($event['quarantineStatus'] ?? null, MySQLRepository::QUARANTINE_ACTIVE, true)) Response::error('The file is in quarantine; release it before scanning it on the computer', 'FILE_QUARANTINED', 409);
        if (in_array($event['scanState'] ?? null, ['Pending', 'Scanning'], true)) Response::error('A scan for this file is already waiting for the agent', 'SCAN_PENDING', 409);
        $scanId = MySQLRepository::requestScan($event, (int)$user['id']);
        MySQLRepository::log((int)$user['id'], 'SCAN_REQUESTED', "Requested scan of {$event['fileName']} on {$event['computerHostname']}", 'scan', (string)$scanId);
        Response::success('Scan requested. The agent on ' . $event['computerHostname'] . ' will scan the file shortly.', ['scanId' => $scanId, 'file' => MySQLRepository::findFileEvent((int)$event['id'])], 201);
    }

    /**
     * Asks the computer's agent to move the file into its quarantine folder (Admin, explicit confirmation).
     * The agent only moves the file if it is still inside a monitored folder and its SHA-256 is unchanged.
     */
    public static function quarantineFile(int $fileEventId, ?int $scanId = null): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        $event = MySQLRepository::findFileEvent($fileEventId);
        if (!$event) Response::error('File not found', 'NOT_FOUND', 404);
        if ((Validation::body()['confirm'] ?? false) !== true) Validation::fail(['confirm' => 'Confirm that the file should be moved into quarantine']);
        if ($event['eventType'] === 'deleted') Response::error('The file was deleted, so it cannot be quarantined', 'FILE_DELETED', 409);
        if (in_array($event['scanState'] ?? null, ['Pending', 'Scanning'], true)) Response::error('Wait until the current scan of this file has finished', 'SCAN_PENDING', 409);
        $hash = $event['sha256'] ?? null;
        if ($scanId !== null) { $scan = MySQLRepository::find('scans', $scanId); $hash = $scan['fileHash'] ?? $hash; }
        if ($hash === null || !preg_match('/^[0-9a-f]{64}$/', $hash)) Response::error('The file has no SHA-256, so the agent could not verify it is the same file. Scan it first.', 'NO_HASH', 409);
        if (MySQLRepository::activeQuarantineForFile((int)$event['id'])) Response::error('This file is already in quarantine (or a quarantine action is pending)', 'ALREADY_QUARANTINED', 409);
        $itemId = MySQLRepository::createQuarantine($event, $scanId ?? ($event['scanId'] !== null ? (int)$event['scanId'] : null), $hash, (int)$user['id']);
        MySQLRepository::log((int)$user['id'], 'QUARANTINE_REQUESTED', "Requested quarantine of {$event['fileName']} on {$event['computerHostname']}", 'quarantine', (string)$itemId);
        Response::success('Quarantine requested. The agent on ' . $event['computerHostname'] . ' will move the file into quarantine shortly.', MySQLRepository::findQuarantine($itemId), 201);
    }
}
