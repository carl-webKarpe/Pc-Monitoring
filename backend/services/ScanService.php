<?php
declare(strict_types=1);

require_once __DIR__ . '/../repositories/MySQLRepository.php';
require_once __DIR__ . '/../helpers/FileAnalyzer.php';
require_once __DIR__ . '/../helpers/Antivirus.php';
require_once __DIR__ . '/../helpers/ScanClassifier.php';
require_once __DIR__ . '/../helpers/VirusTotal.php';

// Collects scan evidence (antivirus engines, VirusTotal, blocklist, static analysis), classifies it and stores the result.
final class ScanService
{
    private const AUTO_SCAN_LIMIT = 20;          // automatic scans per computer per 10 minutes (a burst of new files)
    private const VT_ANALYSIS_TIMEOUT_MINUTES = 20;
    public const ENGINE_NAMES = ['Microsoft Defender', 'ClamAV'];

    // ---- results from a lab-PC agent ----------------------------------------------------------------------

    /** Builds the evidence for a scan the agent finished. Only the SHA-256 is looked up online. */
    public static function evidenceFromAgent(array $data, ?string $sha256): array
    {
        return [
            'source' => 'agent',
            'engines' => self::cleanEngines($data['engines'] ?? []),
            'indicators' => FileRisk::cleanFindings($data['indicators'] ?? $data['findings'] ?? []),
            'fileType' => self::cleanFileType($data['fileType'] ?? null),
            'virusTotal' => $sha256 !== null ? MySQLRepository::hashReputation($sha256) : ['status' => 'unavailable', 'reason' => 'No SHA-256 (file larger than the agent\'s hashing limit)'],
            'blocklist' => MySQLRepository::blocklistMatch($sha256),
            'hashAvailable' => $sha256 !== null,
            'analyzerVersion' => is_string($data['analyzerVersion'] ?? null) && preg_match('/^[\d.]{1,10}$/', $data['analyzerVersion']) ? $data['analyzerVersion'] : '1.0',
            'download' => self::cleanDownload($data['download'] ?? null),
        ];
    }

    public static function finishAgentScan(array $scan, array $data, ?string $sha256, int $durationMs): array
    {
        if (($data['outcome'] ?? '') !== 'completed') {
            $error = is_string($data['error'] ?? null) && ($text = self::cleanText($data['error'], 200)) !== '' ? $text : 'Scan failed on the computer';
            $evidence = ['source' => 'agent', 'error' => $error];
            return MySQLRepository::completeScan($scan, $evidence, ScanClassifier::classify($evidence), null, null, $durationMs);
        }
        $hash = $sha256 ?? ($scan['fileHash'] !== null && preg_match('/^[0-9a-f]{64}$/i', $scan['fileHash']) ? $scan['fileHash'] : null);
        $evidence = self::evidenceFromAgent($data, $hash);
        $size = is_int($data['fileSize'] ?? null) && $data['fileSize'] >= 0 ? $data['fileSize'] : null;
        return MySQLRepository::completeScan($scan, $evidence, ScanClassifier::classify($evidence), $sha256, $size, $durationMs);
    }

    // Engine results reported by the agent: known engines and values only.
    private static function cleanEngines(mixed $engines): array
    {
        if (!is_array($engines)) return [];
        $clean = [];
        foreach (array_slice($engines, 0, 4) as $engine) {
            if (!is_array($engine) || !in_array($engine['name'] ?? null, self::ENGINE_NAMES, true) || !in_array($engine['result'] ?? null, ['clean', 'detected', 'error', 'unavailable'], true)) continue;
            $version = static fn($value) => is_string($value) && preg_match('/^[A-Za-z0-9._ -]{1,40}$/', $value) ? $value : null;
            $clean[] = ['name' => $engine['name'], 'version' => $version($engine['version'] ?? null), 'signatureVersion' => $version($engine['signatureVersion'] ?? null), 'result' => $engine['result'],
                'signature' => $engine['result'] === 'detected' ? (self::cleanText($engine['signature'] ?? '', 120) ?: 'a threat') : null, 'detail' => self::cleanText($engine['detail'] ?? '', 200)];
        }
        return $clean;
    }

    private static function cleanFileType(mixed $type): ?array
    {
        if (!is_array($type) || !is_string($type['family'] ?? null)) return null;
        $label = FileAnalyzer::FAMILIES[$type['family']][0] ?? null;
        if ($label === null) return null;
        $extension = is_string($type['extension'] ?? null) && preg_match('/^[a-z0-9]{0,16}$/', $type['extension']) ? $type['extension'] : '';
        return ['family' => $type['family'], 'label' => $label, 'extension' => $extension, 'extensionMatches' => ($type['extensionMatches'] ?? true) === true];
    }

    // Windows "Mark of the Web": the zone and the site the file came from (query strings are removed by the agent too).
    private static function cleanDownload(mixed $download): ?array
    {
        if (!is_array($download) || !is_int($download['zone'] ?? null)) return null;
        return ['zone' => max(0, min(4, $download['zone'])), 'hostUrl' => self::cleanUrl($download['hostUrl'] ?? null)];
    }

    public static function cleanUrl(mixed $url): ?string
    {
        if (!is_string($url) || !preg_match('#^https?://[^\s<>"]{1,490}$#i', $url)) return null;
        $parts = parse_url($url);
        if (!$parts || empty($parts['host'])) return null;
        return strtolower($parts['scheme']) . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '') . ($parts['path'] ?? '');
    }

    public static function cleanText(mixed $text, int $max): string { return is_string($text) ? FileRisk::cut(trim(preg_replace('/[\x00-\x1F\x7F<>]/u', ' ', $text) ?? ''), $max) : ''; }

    // ---- automatic scans of new files (Settings > Scanner > Automatic Scan) -------------------------------

    /** @param array $events newly stored file events (MySQLRepository::insertFileEvents) */
    public static function autoScan(array $events, string $hostname): int
    {
        if (MySQLRepository::setting('autoScan') === '0' || $events === []) return 0;
        $queued = 0;
        foreach ($events as $event) {
            if ($event['type'] !== 'created' || $event['sha256'] === null) continue;
            if (MySQLRepository::recentAutoScans((int)$event['computerId'], 10) >= self::AUTO_SCAN_LIMIT) break; // the rest stay "New" for a manual scan
            MySQLRepository::requestScan($event, null, 'Auto');
            $queued++;
        }
        if ($queued > 0) MySQLRepository::log(null, 'SCAN_REQUESTED', "Automatic scan queued for $queued new file(s) on $hostname", 'computer', (string)$events[0]['computerId']);
        return $queued;
    }

    // ---- files uploaded on the File Scanner page ----------------------------------------------------------

    public static function retentionDays(): int
    {
        $value = MySQLRepository::setting('uploadRetention');
        return $value !== null && preg_match('/^(\d{1,2}) days?$/i', trim($value), $match) ? max(1, min(90, (int)$match[1])) : 7;
    }

    public static function maxUploadBytes(): int
    {
        $toBytes = static function (string $value): int { $value = trim($value); $number = (int)$value; return match (strtolower(substr($value, -1))) { 'g' => $number * 1073741824, 'm' => $number * 1048576, 'k' => $number * 1024, default => $number }; };
        $limits = [mst_config()['max_upload_mb'] * 1048576];
        foreach (['upload_max_filesize', 'post_max_size'] as $setting) { $bytes = $toBytes((string)ini_get($setting)); if ($bytes > 0) $limits[] = $setting === 'post_max_size' ? $bytes - 65536 : $bytes; }
        return max(1, min($limits));
    }

    /** Stores the upload in protected storage and scans it. The stored copy is kept for "Scan Again" until the retention period ends. */
    public static function scanUpload(string $temporaryPath, string $fileName, int $userId, bool $submitToVirusTotal): array
    {
        $started = microtime(true);
        $sha256 = @hash_file('sha256', $temporaryPath);
        if ($sha256 === false) Response::error('The uploaded file could not be read. The server\'s antivirus may have removed it.', 'UPLOAD_UNREADABLE', 422);
        $stored = bin2hex(random_bytes(16)) . '.bin'; // random name, no extension: the copy can never be opened or run by name
        $path = mst_storage_path('uploads/' . $stored);
        if (!@move_uploaded_file($temporaryPath, $path)) Response::error('The server could not store the uploaded file (check that backend/storage is writable).', 'UPLOAD_STORE_FAILED', 500);
        @chmod($path, 0600);
        $scanId = MySQLRepository::createUploadScan($fileName, $sha256, (int)filesize($path), $userId, $stored, self::retentionDays());
        return self::analyzeUpload(MySQLRepository::scanRow($scanId), $path, $submitToVirusTotal, $started);
    }

    public static function storedPath(array $scanRow): ?string { return !empty($scanRow['storedFile']) && preg_match('/^[0-9a-f]{32}\.bin$/', $scanRow['storedFile']) ? mst_storage_path('uploads/' . $scanRow['storedFile']) : null; }

    public static function analyzeUpload(array $scan, string $path, bool $submitToVirusTotal, ?float $started = null): array
    {
        $started ??= microtime(true);
        $duration = static fn() => (int)((microtime(true) - $started) * 1000);
        if (!is_file($path)) {
            $evidence = ['source' => 'upload', 'error' => 'The stored copy of the file is no longer available (the server\'s antivirus may have removed it)'];
            return MySQLRepository::completeScan($scan, $evidence, ScanClassifier::classify($evidence), null, null, $duration());
        }
        $type = FileAnalyzer::identify($path, $scan['fileName']);
        $evidence = [
            'source' => 'upload',
            'fileType' => $type,
            'indicators' => FileAnalyzer::indicators($path, $scan['fileName'], $type),
            'engines' => Antivirus::scan($path),
            'virusTotal' => MySQLRepository::hashReputation($scan['fileHash']),
            'blocklist' => MySQLRepository::blocklistMatch($scan['fileHash']),
            'hashAvailable' => true,
            'analyzerVersion' => FileAnalyzer::VERSION,
            'submittedToVirusTotal' => false,
        ];
        if (!is_file($path)) $evidence['notes'][] = 'The stored copy disappeared during the scan (the server\'s real-time antivirus may have removed it)';
        $final = true;
        // Unknown to VirusTotal: submit the file only when the Admin asked for it and nothing already proves it is High risk.
        if ($submitToVirusTotal && ($evidence['virusTotal']['status'] ?? '') === 'not_found' && ScanClassifier::classify($evidence)['risk'] !== 'High' && is_file($path)) {
            $upload = VirusTotal::upload($path, $scan['fileName']);
            if ($upload['status'] === 'queued') {
                $evidence['virusTotal'] = ['status' => 'pending', 'analysisId' => $upload['analysisId'], 'link' => VirusTotal::link($scan['fileHash'])];
                $evidence['submittedToVirusTotal'] = true;
                MySQLRepository::markVirusTotalChecked((int)$scan['id'], $upload['analysisId']);
                $final = false;
            } else {
                $evidence['notes'][] = 'Upload to VirusTotal failed: ' . ($upload['reason'] ?? $upload['status']);
            }
        }
        return MySQLRepository::completeScan($scan, $evidence, ScanClassifier::classify($evidence), null, (int)@filesize($path) ?: null, $duration(), $final);
    }

    /** Checks VirusTotal for uploads still being analysed (called while people browse scan results). */
    public static function refreshPendingVirusTotal(int $limit = 2): void
    {
        foreach (MySQLRepository::scansWaitingForVirusTotal($limit) as $scan) {
            $details = json_decode((string)$scan['scanDetails'], true) ?: [];
            unset($details['factors'], $details['recommendations']);
            $result = VirusTotal::analysis((string)$scan['vtAnalysisId'], (string)$scan['fileHash']);
            MySQLRepository::markVirusTotalChecked((int)$scan['id']);
            $waited = time() - (strtotime((string)$scan['startedAt']) ?: time());
            if ($result['status'] === 'found') { MySQLRepository::saveReputation($scan['fileHash'], $result); $details['virusTotal'] = $result + ['submitted' => true]; }
            elseif ($result['status'] === 'unavailable' || $waited > self::VT_ANALYSIS_TIMEOUT_MINUTES * 60) $details['virusTotal'] = ['status' => 'unavailable', 'reason' => $result['reason'] ?? 'VirusTotal did not finish the analysis within ' . self::VT_ANALYSIS_TIMEOUT_MINUTES . ' minutes'];
            else continue;
            MySQLRepository::completeScan($scan, $details, ScanClassifier::classify($details), null, null, $waited * 1000);
        }
    }

    /** Retention policy: uploaded copies are deleted when their retention period ends. */
    public static function deleteExpiredUploads(): void
    {
        foreach (MySQLRepository::expiredStoredFiles() as $expired) {
            if (preg_match('/^[0-9a-f]{32}\.bin$/', (string)$expired['storedFile'])) @unlink(mst_storage_path('uploads/' . $expired['storedFile']));
            MySQLRepository::clearStoredFile($expired['id']);
        }
    }
}
