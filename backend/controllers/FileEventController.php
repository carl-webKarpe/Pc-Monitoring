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
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    private static function list(): never
    {
        RoleMiddleware::allowModule('computer_monitoring');
        $filters = Validation::filters(['computerId' => ['computer_id', 'id'], 'type' => ['event_type', ['created', 'deleted']], 'status' => ['status', ['New', 'Reviewed', 'Scan Requested', 'Scanned', 'Scan Failed']]]);
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
        if ($event['eventType'] !== 'created') Response::error('Only files that still exist can be scanned', 'FILE_DELETED', 409);
        if ($event['status'] === 'Scan Requested' && $event['scanStatus'] === 'PENDING') Response::error('A scan for this file is already waiting for the agent', 'SCAN_PENDING', 409);
        $scanId = MySQLRepository::requestScan($event, (int)$user['id']);
        MySQLRepository::log((int)$user['id'], 'SCAN_REQUESTED', "Requested scan of {$event['fileName']} on {$event['computerHostname']}", 'scan', (string)$scanId);
        Response::success('Scan requested. The agent on ' . $event['computerHostname'] . ' will scan the file shortly.', ['scanId' => $scanId, 'file' => MySQLRepository::findFileEvent((int)$event['id'])], 201);
    }
}
