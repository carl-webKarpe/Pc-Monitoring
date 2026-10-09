<?php
declare(strict_types=1);

require_once __DIR__ . '/ResourceController.php';
require_once __DIR__ . '/../services/ScanService.php';

// File Scanner page (Admin only): upload a file to the MST server and scan it with the server's antivirus engines,
// VirusTotal and static analysis. The file is never opened or run.
final class FileScannerController
{
    public static function index(string $method): never
    {
        if ($method === 'GET') self::capabilities();
        if ($method === 'POST') self::upload();
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    // What this server can scan with, so the page shows real limits and engines (never placeholder values).
    private static function capabilities(): never
    {
        RoleMiddleware::allowModule('file_scanner');
        ScanService::deleteExpiredUploads();
        Response::success('Scanner capabilities', [
            'maxUploadBytes' => ScanService::maxUploadBytes(),
            'engines' => array_map(fn($engine) => ['name' => $engine['name'], 'available' => $engine['available'], 'version' => $engine['version'], 'signatureVersion' => $engine['signatureVersion'], 'detail' => $engine['detail']], Antivirus::status()),
            'virusTotal' => ['configured' => VirusTotal::configured(), 'requestsPerMinute' => mst_config()['virustotal_requests_per_minute']],
            'retentionDays' => ScanService::retentionDays(),
            'autoScan' => MySQLRepository::setting('autoScan') !== '0',
        ]);
    }

    private static function upload(): never
    {
        $user = RoleMiddleware::allowModule('file_scanner');
        ScanService::deleteExpiredUploads();
        $limit = ScanService::maxUploadBytes();
        $tooLarge = 'The file is larger than the ' . self::megabytes($limit) . ' upload limit.';
        // PHP drops the whole request body when it exceeds post_max_size, so check the declared size first.
        if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > $limit + 65536) Response::error($tooLarge, 'FILE_TOO_LARGE', 413);
        $file = $_FILES['file'] ?? null;
        if (!is_array($file) || is_array($file['error'] ?? null)) Validation::fail(['file' => 'Choose one file to scan']);
        $uploadError = (int)$file['error'];
        if (in_array($uploadError, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true)) Response::error($tooLarge, 'FILE_TOO_LARGE', 413);
        if ($uploadError === UPLOAD_ERR_NO_FILE) Validation::fail(['file' => 'Choose one file to scan']);
        if ($uploadError === UPLOAD_ERR_PARTIAL) Response::error('The upload was interrupted. Try again.', 'UPLOAD_PARTIAL', 400);
        if ($uploadError !== UPLOAD_ERR_OK) { error_log("Upload error code $uploadError"); Response::error('The server could not receive the file (PHP upload error ' . $uploadError . ').', 'UPLOAD_FAILED', 500); }
        if (!is_uploaded_file($file['tmp_name'])) Response::error('Invalid upload', 'UPLOAD_FAILED', 400);
        $size = (int)$file['size'];
        if ($size === 0) Validation::fail(['file' => 'The file is empty, so there is nothing to scan']);
        if ($size > $limit) Response::error($tooLarge, 'FILE_TOO_LARGE', 413);
        $name = self::cleanFileName((string)$file['name']);
        if ($name === '') Validation::fail(['file' => 'The file name is invalid']);
        $submit = in_array($_POST['submitToVirusTotal'] ?? '0', ['1', 'true'], true);
        $force = in_array($_POST['force'] ?? '0', ['1', 'true'], true);

        // Duplicate detection: the same content was scanned in the last 24 hours.
        $sha256 = hash_file('sha256', $file['tmp_name']);
        if (!$force && $sha256 !== false && ($previous = MySQLRepository::recentScanOfHash($sha256))) {
            @unlink($file['tmp_name']);
            Response::success('This file was already scanned in the last 24 hours', ['duplicate' => true, 'scan' => $previous]);
        }
        $scan = ScanService::scanUpload($file['tmp_name'], $name, (int)$user['id'], $submit);
        MySQLRepository::log((int)$user['id'], 'FILE_UPLOAD_SCANNED', "Uploaded and scanned $name: " . ($scan['scanState'] === 'Scanning' ? 'waiting for VirusTotal' : $scan['riskLevel']) . ($submit ? ' (submitted to VirusTotal)' : ''), 'scan', (string)$scan['id']);
        Response::success($scan['scanState'] === 'Scanning' ? 'Scanned. VirusTotal is still analysing the file.' : 'Scan completed', ['duplicate' => false, 'scan' => $scan], 201);
    }

    private static function megabytes(int $bytes): string { return rtrim(rtrim(number_format($bytes / 1048576, 1), '0'), '.') . ' MB'; }

    // Display name only (the stored copy gets a random name): no folders, no control characters, at most 255 characters.
    private static function cleanFileName(string $name): string
    {
        $name = basename(str_replace('\\', '/', $name));
        $name = trim(preg_replace('/[\x00-\x1F\x7F<>:"|?*]/u', '_', $name) ?? '');
        return $name === '.' || $name === '..' ? '' : FileRisk::cut($name, 255);
    }
}
