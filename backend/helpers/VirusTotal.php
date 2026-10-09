<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/FileRisk.php';

// VirusTotal API v3 file-hash lookup. Only the SHA-256 is sent; files never leave the lab PC.
final class VirusTotal
{
    private const TIMEOUT_SECONDS = 8;

    public static function configured(): bool { return mst_config()['virustotal_api_key'] !== ''; }

    /**
     * @return array{status: string, malicious?: int, suspicious?: int, harmless?: int, undetected?: int, total?: int, name?: ?string, link?: string, reason?: string}
     * status: found | not_found | unavailable | not_configured
     */
    public static function lookup(string $sha256): array
    {
        if (!self::configured()) return ['status' => 'not_configured'];
        if (!preg_match('/^[0-9a-f]{64}$/i', $sha256)) return ['status' => 'unavailable', 'reason' => 'Invalid hash'];
        $config = mst_config();
        [$status, $body, $error] = self::get($config['virustotal_api_url'] . '/files/' . strtolower($sha256), $config['virustotal_api_key'], $config['virustotal_ca_bundle']);
        if ($error !== null) { error_log('VirusTotal lookup failed: ' . $error); return ['status' => 'unavailable', 'reason' => 'VirusTotal could not be reached']; }
        if ($status === 404) return ['status' => 'not_found', 'link' => self::link($sha256)];
        if ($status === 401 || $status === 403) return ['status' => 'unavailable', 'reason' => 'VirusTotal API key was rejected'];
        if ($status === 429) return ['status' => 'unavailable', 'reason' => 'VirusTotal request limit reached; try again later'];
        $json = json_decode((string)$body, true);
        $stats = $json['data']['attributes']['last_analysis_stats'] ?? null;
        if ($status !== 200 || !is_array($stats)) return ['status' => 'unavailable', 'reason' => "Unexpected VirusTotal response (HTTP $status)"];
        $count = static fn(string $key): int => max(0, (int)($stats[$key] ?? 0));
        return [
            'status' => 'found',
            'malicious' => $count('malicious'),
            'suspicious' => $count('suspicious'),
            'harmless' => $count('harmless'),
            'undetected' => $count('undetected'),
            'total' => array_sum(array_map(static fn($value) => max(0, (int)$value), $stats)),
            'name' => is_string($json['data']['attributes']['meaningful_name'] ?? null) ? FileRisk::cut($json['data']['attributes']['meaningful_name'], 120) : null,
            'link' => self::link($sha256),
        ];
    }

    public static function link(string $sha256): string { return 'https://www.virustotal.com/gui/file/' . strtolower($sha256); }

    /** @return array{0: int, 1: ?string, 2: ?string} [HTTP status, body, transport error] */
    private static function get(string $url, string $apiKey, string $caBundle): array
    {
        $headers = ['x-apikey: ' . $apiKey, 'Accept: application/json'];
        if (function_exists('curl_init')) {
            $curl = curl_init($url);
            $options = [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => self::TIMEOUT_SECONDS, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_FOLLOWLOCATION => false];
            // Windows PHP often has no CA bundle configured: use the Windows certificate store, or an explicit bundle.
            if ($caBundle !== '') $options[CURLOPT_CAINFO] = $caBundle;
            elseif (defined('CURLSSLOPT_NATIVE_CA')) $options[CURLOPT_SSL_OPTIONS] = CURLSSLOPT_NATIVE_CA;
            curl_setopt_array($curl, $options);
            $body = curl_exec($curl);
            $error = $body === false ? curl_error($curl) : null;
            $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            curl_close($curl);
            return [$status, $body === false ? null : (string)$body, $error];
        }
        $context = stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", $headers), 'timeout' => self::TIMEOUT_SECONDS, 'ignore_errors' => true], 'ssl' => $caBundle !== '' ? ['cafile' => $caBundle] : []]);
        $body = @file_get_contents($url, false, $context);
        $status = isset($http_response_header[0]) && preg_match('/\s(\d{3})\s?/', $http_response_header[0], $match) ? (int)$match[1] : 0;
        return [$status, $body === false ? null : $body, $body === false && $status === 0 ? 'connection failed' : null];
    }
}
