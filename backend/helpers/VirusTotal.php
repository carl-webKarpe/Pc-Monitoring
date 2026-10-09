<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/FileRisk.php';

// VirusTotal API v3. Files detected on lab PCs are only looked up by SHA-256 (they never leave the PC).
// A file uploaded on the File Scanner page can also be submitted to VirusTotal when the Admin explicitly chooses
// to: VirusTotal then shares it with security vendors, so confidential files must not be submitted.
final class VirusTotal
{
    private const TIMEOUT_SECONDS = 8;
    private const UPLOAD_TIMEOUT_SECONDS = 120;
    public const MAX_UPLOAD_BYTES = 32 * 1024 * 1024; // larger files need VirusTotal's upload_url flow

    public static function configured(): bool { return mst_config()['virustotal_api_key'] !== ''; }

    /**
     * @return array{status: string, malicious?: int, suspicious?: int, harmless?: int, undetected?: int, total?: int, name?: ?string, link?: string, reason?: string}
     * status: found | not_found | unavailable | not_configured
     */
    public static function lookup(string $sha256): array
    {
        if (!self::configured()) return ['status' => 'not_configured'];
        if (!preg_match('/^[0-9a-f]{64}$/i', $sha256)) return ['status' => 'unavailable', 'reason' => 'Invalid hash'];
        [$status, $body, $error] = self::request('GET', '/files/' . strtolower($sha256));
        if ($error !== null) return ['status' => 'unavailable', 'reason' => $error];
        if ($status === 404) return ['status' => 'not_found', 'link' => self::link($sha256)];
        $problem = self::problem($status);
        if ($problem !== null) return ['status' => 'unavailable', 'reason' => $problem];
        $json = json_decode((string)$body, true);
        $stats = $json['data']['attributes']['last_analysis_stats'] ?? null;
        if ($status !== 200 || !is_array($stats)) return ['status' => 'unavailable', 'reason' => "Unexpected VirusTotal response (HTTP $status)"];
        return self::fromStats($stats, $sha256) + ['name' => is_string($json['data']['attributes']['meaningful_name'] ?? null) ? FileRisk::cut($json['data']['attributes']['meaningful_name'], 120) : null];
    }

    /** Submits a file for analysis. @return array{status: string, analysisId?: string, reason?: string} status: queued | unavailable | not_configured */
    public static function upload(string $path, string $fileName): array
    {
        if (!self::configured()) return ['status' => 'not_configured'];
        if (!function_exists('curl_init')) return ['status' => 'unavailable', 'reason' => 'PHP curl extension is required to upload files'];
        if ((int)@filesize($path) > self::MAX_UPLOAD_BYTES) return ['status' => 'unavailable', 'reason' => 'File is larger than 32 MB'];
        [$status, $body, $error] = self::request('POST', '/files', ['file' => new CURLFile($path, 'application/octet-stream', $fileName)]);
        if ($error !== null) return ['status' => 'unavailable', 'reason' => $error];
        $problem = self::problem($status);
        if ($problem !== null) return ['status' => 'unavailable', 'reason' => $problem];
        $id = json_decode((string)$body, true)['data']['id'] ?? null;
        return is_string($id) && preg_match('/^[A-Za-z0-9=_-]{8,160}$/', $id) ? ['status' => 'queued', 'analysisId' => $id] : ['status' => 'unavailable', 'reason' => "Unexpected VirusTotal response (HTTP $status)"];
    }

    /** Result of an uploaded file's analysis. @return array{status: string, ...} status: found (completed) | pending | unavailable */
    public static function analysis(string $analysisId, string $sha256): array
    {
        if (!self::configured()) return ['status' => 'unavailable', 'reason' => 'VirusTotal is not configured'];
        [$status, $body, $error] = self::request('GET', '/analyses/' . rawurlencode($analysisId));
        if ($error !== null) return ['status' => 'pending', 'reason' => $error];
        $problem = self::problem($status);
        if ($problem !== null) return ['status' => $status === 429 ? 'pending' : 'unavailable', 'reason' => $problem];
        $attributes = json_decode((string)$body, true)['data']['attributes'] ?? null;
        if ($status !== 200 || !is_array($attributes)) return ['status' => 'unavailable', 'reason' => "Unexpected VirusTotal response (HTTP $status)"];
        if (($attributes['status'] ?? '') !== 'completed') return ['status' => 'pending'];
        return self::fromStats(is_array($attributes['stats'] ?? null) ? $attributes['stats'] : [], $sha256);
    }

    public static function link(string $sha256): string { return 'https://www.virustotal.com/gui/file/' . strtolower($sha256); }

    private static function fromStats(array $stats, string $sha256): array
    {
        $count = static fn(string $key): int => max(0, (int)($stats[$key] ?? 0));
        // "total" counts engines that gave a verdict; engines that timed out or do not support the file type are left out.
        return ['status' => 'found', 'malicious' => $count('malicious'), 'suspicious' => $count('suspicious'), 'harmless' => $count('harmless'), 'undetected' => $count('undetected'),
            'total' => $count('malicious') + $count('suspicious') + $count('harmless') + $count('undetected'), 'link' => self::link($sha256)];
    }

    private static function problem(int $status): ?string
    {
        return match (true) {
            $status === 401, $status === 403 => 'VirusTotal API key was rejected',
            $status === 429 => 'VirusTotal request limit reached; try again later',
            $status === 413 => 'VirusTotal refused the file (too large)',
            $status >= 500 => "VirusTotal is unavailable (HTTP $status)",
            default => null,
        };
    }

    /** @return array{0: int, 1: ?string, 2: ?string} [HTTP status, body, problem] */
    private static function request(string $method, string $path, ?array $form = null): array
    {
        if (!self::reserveSlot()) return [0, null, 'MST paused VirusTotal requests to stay within ' . mst_config()['virustotal_requests_per_minute'] . ' per minute; scan again in a minute'];
        $config = mst_config();
        $url = $config['virustotal_api_url'] . $path;
        $headers = ['x-apikey: ' . $config['virustotal_api_key'], 'Accept: application/json'];
        if (function_exists('curl_init')) {
            $curl = curl_init($url);
            $options = [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => $form === null ? self::TIMEOUT_SECONDS : self::UPLOAD_TIMEOUT_SECONDS, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_FOLLOWLOCATION => false];
            if ($method === 'POST') { $options[CURLOPT_POST] = true; $options[CURLOPT_POSTFIELDS] = $form ?? []; }
            // Windows PHP often has no CA bundle configured: use the Windows certificate store, or an explicit bundle.
            if ($config['virustotal_ca_bundle'] !== '') $options[CURLOPT_CAINFO] = $config['virustotal_ca_bundle'];
            elseif (defined('CURLSSLOPT_NATIVE_CA')) $options[CURLOPT_SSL_OPTIONS] = CURLSSLOPT_NATIVE_CA;
            curl_setopt_array($curl, $options);
            $body = curl_exec($curl);
            $error = $body === false ? curl_error($curl) : null;
            $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            curl_close($curl);
            if ($error !== null) { error_log('VirusTotal request failed: ' . $error); return [0, null, 'VirusTotal could not be reached']; }
            return [$status, (string)$body, null];
        }
        $context = stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", $headers), 'timeout' => self::TIMEOUT_SECONDS, 'ignore_errors' => true], 'ssl' => $config['virustotal_ca_bundle'] !== '' ? ['cafile' => $config['virustotal_ca_bundle']] : []]);
        $body = @file_get_contents($url, false, $context);
        $status = isset($http_response_header[0]) && preg_match('/\s(\d{3})\s?/', $http_response_header[0], $match) ? (int)$match[1] : 0;
        return [$status, $body === false ? null : $body, $body === false && $status === 0 ? 'VirusTotal could not be reached' : null];
    }

    // Sliding one-minute window shared by all API requests (lookups, uploads, analysis checks).
    private static function reserveSlot(): bool
    {
        $handle = @fopen(mst_storage_path('virustotal-rate.json'), 'c+');
        if (!$handle) return true;
        flock($handle, LOCK_EX);
        $times = json_decode((string)stream_get_contents($handle), true);
        $now = microtime(true);
        $times = array_values(array_filter(is_array($times) ? $times : [], fn($time) => is_numeric($time) && $now - $time < 60));
        $allowed = count($times) < mst_config()['virustotal_requests_per_minute'];
        if ($allowed) $times[] = $now;
        ftruncate($handle, 0); rewind($handle); fwrite($handle, json_encode($times));
        flock($handle, LOCK_UN); fclose($handle);
        return $allowed;
    }
}
