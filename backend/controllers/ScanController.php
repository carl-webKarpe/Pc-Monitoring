<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';
require_once __DIR__ . '/../services/ScanService.php';

// Scan History (Super Admin + Admin can read and export) and scan actions (Admin only, File Scanner module).
final class ScanController
{
    private const RISKS = ['Safe', 'Medium', 'High', 'Unknown', 'Failed'];
    private const STATES = ['Pending', 'Scanning', 'Completed', 'Failed'];
    private const SOURCES = ['Agent', 'Auto', 'Upload'];
    private const SORTS = ['id', 'file', 'computer', 'risk', 'date', 'state'];

    public static function index(string $method, ?string $id = null, ?string $action = null): never
    {
        if ($method === 'GET' && $id === null) self::list();
        if ($method === 'GET' && $id === 'export' && $action === null) self::export();
        if ($id !== null && $id !== 'export') {
            if ($method === 'GET' && $action === null) self::show($id);
            if ($method === 'GET' && $action === 'report') self::report($id);
            if ($method === 'POST' && $action === 'rescan') self::rescan($id);
            if ($method === 'POST' && $action === 'investigate') self::investigate($id);
            if ($method === 'POST' && $action === 'quarantine') self::quarantine($id);
            if ($method === 'DELETE' && $action === 'stored-file') self::deleteStoredFile($id);
        }
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    /** ?q=&risk=&state=&source=&computerId=&from=YYYY-MM-DD&to=&sort=&dir=&limit=&offset= */
    private static function filters(): array
    {
        $filters = []; $errors = [];
        $text = $_GET['q'] ?? '';
        if (!is_string($text) || strlen($text) > 100) $errors['q'] = 'Search text is too long'; elseif (trim($text) !== '') $filters['q'] = trim($text);
        foreach (['risk' => self::RISKS, 'state' => self::STATES, 'source' => self::SOURCES] as $key => $allowed) {
            if (!isset($_GET[$key]) || $_GET[$key] === '') continue;
            if (!is_string($_GET[$key]) || !in_array($_GET[$key], $allowed, true)) $errors[$key] = "$key must be one of: " . implode(', ', $allowed); else $filters[$key] = $_GET[$key];
        }
        if (isset($_GET['computerId']) && $_GET['computerId'] !== '') { if (!is_string($_GET['computerId']) || !ctype_digit($_GET['computerId']) || (int)$_GET['computerId'] < 1) $errors['computerId'] = 'computerId must be a positive number'; else $filters['computerId'] = (int)$_GET['computerId']; }
        foreach (['from', 'to'] as $key) {
            if (!isset($_GET[$key]) || $_GET[$key] === '') continue;
            $date = is_string($_GET[$key]) ? DateTimeImmutable::createFromFormat('!Y-m-d', $_GET[$key]) : false;
            if (!$date || $date->format('Y-m-d') !== $_GET[$key]) $errors[$key] = "$key must be a date (YYYY-MM-DD)"; else $filters[$key] = $_GET[$key];
        }
        if ($errors !== []) Validation::fail($errors);
        return $filters;
    }

    private static function sorting(): array
    {
        $sort = $_GET['sort'] ?? 'id'; $direction = $_GET['dir'] ?? 'desc';
        if (!is_string($sort) || !in_array($sort, self::SORTS, true)) Validation::fail(['sort' => 'sort must be one of: ' . implode(', ', self::SORTS)]);
        if (!in_array($direction, ['asc', 'desc'], true)) Validation::fail(['dir' => 'dir must be asc or desc']);
        return [$sort, $direction];
    }

    private static function list(): never
    {
        RoleMiddleware::allowModule('scan_history');
        ScanService::refreshPendingVirusTotal();
        $filters = self::filters();
        [$sort, $direction] = self::sorting();
        [$limit, $offset] = Validation::page(25, 100);
        [$rows, $total] = MySQLRepository::searchScans($filters, $sort, $direction, $limit, $offset);
        Response::success('Request successful', $rows, 200, ['total' => $total, 'limit' => $limit, 'offset' => $offset]);
    }

    private static function findOrFail(string $id): array
    {
        $scan = MySQLRepository::find('scans', Validation::id($id));
        if (!$scan) Response::error('Scan not found', 'NOT_FOUND', 404);
        return $scan;
    }

    private static function show(string $id): never
    {
        RoleMiddleware::allowModule('scan_history');
        ScanService::refreshPendingVirusTotal();
        $scan = self::findOrFail($id);
        $scan['threat'] = MySQLRepository::threatForScan((int)$scan['id']);
        $scan['sameHash'] = $scan['fileHash'] && preg_match('/^[0-9a-f]{64}$/', $scan['fileHash']) ? MySQLRepository::scansOfHash($scan['fileHash'], (int)$scan['id']) : [];
        Response::success('Request successful', $scan);
    }

    // ---- actions (Admin) ---------------------------------------------------------------------------------

    private static function rescan(string $id): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        $scan = self::findOrFail($id);
        if ($scan['source'] === 'Upload') {
            $row = MySQLRepository::scanRow((int)$scan['id']);
            $path = ScanService::storedPath($row);
            if ($path === null || !is_file($path)) Response::error('The uploaded copy is no longer stored (retention period over or deleted). Upload the file again to scan it.', 'STORED_FILE_GONE', 409);
            $newId = MySQLRepository::createUploadScan($scan['fileName'], $scan['fileHash'], (int)$scan['fileSize'], (int)$user['id'], null, ScanService::retentionDays());
            MySQLRepository::moveStoredFile((int)$scan['id'], $newId);
            $result = ScanService::analyzeUpload(MySQLRepository::scanRow($newId), $path, (Validation::body()['submitToVirusTotal'] ?? false) === true);
            MySQLRepository::log((int)$user['id'], 'SCAN_REQUESTED', "Scanned {$scan['fileName']} again (uploaded copy, scan #{$scan['id']} -> #$newId): {$result['riskLevel']}", 'scan', (string)$newId);
            Response::success('Scan completed', $result, 201);
        }
        if ($scan['fileEventId'] === null) Response::error('This scan is not linked to a file on a lab computer', 'NO_FILE', 409);
        $event = MySQLRepository::findFileEvent((int)$scan['fileEventId']);
        if (!$event || $event['eventType'] === 'deleted') Response::error('The file was deleted, so it can no longer be scanned', 'FILE_DELETED', 409);
        if (in_array($event['quarantineStatus'] ?? null, MySQLRepository::QUARANTINE_ACTIVE, true)) Response::error('The file is in quarantine; release it before scanning it on the computer', 'FILE_QUARANTINED', 409);
        if (in_array($event['scanState'] ?? null, ['Pending', 'Scanning'], true)) Response::error('A scan for this file is already waiting for the agent', 'SCAN_PENDING', 409);
        $newId = MySQLRepository::requestScan($event, (int)$user['id']);
        MySQLRepository::log((int)$user['id'], 'SCAN_REQUESTED', "Requested a new scan of {$event['fileName']} on {$event['computerHostname']} (after scan #{$scan['id']})", 'scan', (string)$newId);
        Response::success('Scan requested. The agent on ' . $event['computerHostname'] . ' will scan the file shortly.', MySQLRepository::find('scans', $newId), 201);
    }

    private static function investigate(string $id): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        $scan = self::findOrFail($id);
        $threat = MySQLRepository::threatForScan((int)$scan['id']);
        if ($threat && $threat['status'] === 'Detected') { $threat = MySQLRepository::updateThreatStatus((int)$threat['id'], 'Investigating'); }
        MySQLRepository::log((int)$user['id'], 'SCAN_INVESTIGATED', "Investigation opened for scan #{$scan['id']} ({$scan['fileName']}, {$scan['riskClass']})" . ($threat ? " - threat #{$threat['id']} is {$threat['status']}" : ''), 'scan', (string)$scan['id']);
        Response::success('Investigation opened', [
            'scan' => $scan,
            'threat' => $threat,
            'sameHash' => $scan['fileHash'] && preg_match('/^[0-9a-f]{64}$/', $scan['fileHash']) ? MySQLRepository::scansOfHash($scan['fileHash'], (int)$scan['id']) : [],
            'nearbyFileEvents' => $scan['computerId'] !== null ? MySQLRepository::recentFileEventsForComputer((int)$scan['computerId'], (string)($scan['completedAt'] ?? $scan['createdAt'])) : [],
        ]);
    }

    private static function quarantine(string $id): never
    {
        RoleMiddleware::allowModule('file_scanner');
        $scan = self::findOrFail($id);
        if ($scan['fileEventId'] === null) Response::error('Only files on lab computers can be quarantined (uploaded copies are already kept in protected storage)', 'NO_FILE', 409);
        FileEventController::quarantineFile((int)$scan['fileEventId'], (int)$scan['id']);
    }

    private static function deleteStoredFile(string $id): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        $scan = self::findOrFail($id);
        $row = MySQLRepository::scanRow((int)$scan['id']);
        $path = ScanService::storedPath($row);
        if ($path === null) Response::error('No uploaded copy is stored for this scan', 'NO_STORED_FILE', 409);
        if (is_file($path) && !@unlink($path)) Response::error('The stored copy could not be deleted', 'DELETE_FAILED', 500);
        MySQLRepository::clearStoredFile((int)$scan['id']);
        MySQLRepository::log((int)$user['id'], 'UPLOAD_DELETED', "Deleted the stored copy of {$scan['fileName']} (scan #{$scan['id']}); the scan record is kept", 'scan', (string)$scan['id']);
        Response::success('Stored copy deleted. The scan record is kept for the audit trail.', MySQLRepository::find('scans', (int)$scan['id']));
    }

    // ---- reports (Super Admin + Admin) -------------------------------------------------------------------

    private static function export(): never
    {
        $user = RoleMiddleware::allowModule('scan_history');
        $filters = self::filters();
        [$sort, $direction] = self::sorting();
        [$rows, $total] = MySQLRepository::searchScans($filters, $sort, $direction, 5000, 0);
        MySQLRepository::log((int)$user['id'], 'REPORT_EXPORTED', 'Exported ' . count($rows) . " scan record(s) as CSV" . ($filters ? ' (filtered)' : ''), 'scan', null);
        $output = fopen('php://temp', 'w+');
        fwrite($output, "\xEF\xBB\xBF"); // UTF-8 BOM so Excel shows non-English file names correctly
        fputcsv($output, ['Scan ID', 'File Name', 'Computer', 'Source', 'SHA-256', 'Risk Level', 'Detection', 'Evidence Strength', 'Coverage', 'Scan Date', 'Scanner', 'Status', 'Requested By'], ',', '"', '');
        foreach ($rows as $scan) {
            fputcsv($output, array_map([self::class, 'csvCell'], [self::code($scan), $scan['fileName'], $scan['computerHostname'] ?? 'MST server (upload)', $scan['source'], $scan['fileHash'], $scan['riskClass'] ?? '', $scan['detection'], $scan['evidenceStrength'], $scan['analysisCoverage'], $scan['completedAt'] ?? $scan['createdAt'], $scan['scanner'], $scan['scanState'], $scan['createdByUsername'] ?? 'System']), ',', '"', '');
        }
        rewind($output);
        self::download('MST-scan-history-' . date('Ymd-His') . '.csv', 'text/csv; charset=utf-8', (string)stream_get_contents($output));
    }

    private static function report(string $id): never
    {
        $user = RoleMiddleware::allowModule('scan_history');
        $scan = self::findOrFail($id);
        $details = json_decode((string)$scan['scanDetails'], true) ?: [];
        $line = static fn(string $label, mixed $value): string => str_pad($label, 20) . ': ' . ($value === null || $value === '' ? '-' : $value) . "\n";
        $text = "MONITORING SYSTEM THREAT - FILE SCAN REPORT\n" . str_repeat('=', 60) . "\n";
        $text .= $line('Scan ID', self::code($scan)) . $line('File name', $scan['fileName']) . $line('Location', $scan['filePath'] ?? 'Uploaded on the File Scanner page')
            . $line('Computer', $scan['computerHostname'] ? "{$scan['computerHostname']} ({$scan['computerDeviceId']})" : 'MST server (upload)') . $line('File size', $scan['fileSize'] !== null ? number_format((int)$scan['fileSize']) . ' bytes' : null)
            . $line('File type', $scan['fileType']) . $line('SHA-256', $scan['fileHash']) . "\n";
        $text .= $line('Risk level', $scan['riskClass']) . $line('Detection', $scan['detection']) . $line('Evidence strength', $scan['evidenceStrength']) . $line('Analysis coverage', $scan['analysisCoverage'])
            . $line('Status', $scan['scanState']) . $line('Scanner', $scan['scanner']) . $line('Requested', $scan['createdAt'] . ' by ' . ($scan['createdByUsername'] ?? 'System (automatic)'))
            . $line('Completed', $scan['completedAt']) . $line('Duration', $scan['duration']) . "\n";
        if ($scan['riskClass'] === 'Safe') $text .= "NOTE: Safe means the configured scanners found no threat. It does not guarantee the file is completely safe.\n\n";
        $text .= "ANTIVIRUS ENGINES\n";
        foreach ($details['engines'] ?? [] as $engine) $text .= '  - ' . $engine['name'] . ' ' . ($engine['version'] ?? '') . ': ' . strtoupper($engine['result']) . ($engine['signature'] ? ' (' . $engine['signature'] . ')' : '') . ($engine['detail'] ? ' - ' . $engine['detail'] : '') . "\n";
        if (empty($details['engines'])) $text .= "  - No antivirus engine result\n";
        $vt = $details['virusTotal'] ?? null;
        $text .= "\nVIRUSTOTAL\n  " . match ($vt['status'] ?? null) { 'found' => "{$vt['malicious']} of {$vt['total']} vendors flagged it ({$vt['suspicious']} suspicious) - {$vt['link']}", 'not_found' => 'Unknown to VirusTotal', 'pending' => 'Analysis in progress', 'not_configured' => 'Not configured', null => 'Not checked', default => 'Unavailable: ' . ($vt['reason'] ?? '') } . "\n";
        $text .= "\nEVIDENCE\n" . implode('', array_map(fn($factor) => "  - $factor\n", $details['factors'] ?? [$details['error'] ?? 'No details recorded']));
        $text .= "\nRECOMMENDED NEXT STEPS\n" . implode('', array_map(fn($step) => "  - $step\n", $details['recommendations'] ?? ScanClassifier::recommendations((string)$scan['riskClass'])));
        if (!empty($details['download']['zone'])) $text .= "\nDOWNLOAD INFORMATION (Windows Mark of the Web)\n  Zone " . $details['download']['zone'] . ($details['download']['hostUrl'] ? ' - source ' . $details['download']['hostUrl'] : '') . "\n";
        $text .= "\n" . str_repeat('-', 60) . "\nGenerated " . date('Y-m-d H:i:s') . " by {$user['username']} from the MST database.\n";
        MySQLRepository::log((int)$user['id'], 'REPORT_EXPORTED', "Downloaded the report for scan #{$scan['id']} ({$scan['fileName']})", 'scan', (string)$scan['id']);
        self::download('MST-' . self::code($scan) . '-report.txt', 'text/plain; charset=utf-8', str_replace("\n", "\r\n", $text));
    }

    private static function code(array $scan): string { return 'SCN-' . str_pad((string)$scan['id'], 3, '0', STR_PAD_LEFT); }

    // Spreadsheet programs run cells that start with = + - @ as formulas; prefix them so exported names stay text.
    private static function csvCell(mixed $value): string { $text = (string)($value ?? ''); return preg_match('/^[=+\-@\t\r]/', $text) ? "'" . $text : $text; }

    private static function download(string $fileName, string $type, string $body): never
    {
        header('Content-Type: ' . $type);
        header('Content-Disposition: attachment; filename="' . $fileName . '"');
        header('Content-Length: ' . strlen($body));
        echo $body;
        exit;
    }
}
