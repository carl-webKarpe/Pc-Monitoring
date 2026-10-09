<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/FileRisk.php';

// Antivirus engines installed on the MST server, used for files uploaded on the File Scanner page.
// Microsoft Defender (built into Windows) and ClamAV are supported. Files are scanned in place and are never run;
// Defender is called with -DisableRemediation so MST (not Defender) decides what happens to the file.
final class Antivirus
{
    /** Engines that can be used on this server, with why the others cannot. @return array<int, array{name: string, available: bool, version: ?string, signatureVersion: ?string, detail: string}> */
    public static function status(): array
    {
        $engines = [];
        $mode = self::mode();
        if (in_array($mode, ['auto', 'defender'], true)) $engines[] = self::defenderStatus();
        if (in_array($mode, ['auto', 'clamav'], true)) $engines[] = self::clamavStatus();
        return array_values(array_filter($engines, fn($engine) => $engine['available'] || $mode !== 'auto' || $engine['configured']));
    }

    /** Scans one file with every available engine. @return array<int, array{name: string, version: ?string, signatureVersion: ?string, result: string, signature: ?string, detail: string}> */
    public static function scan(string $path): array
    {
        $results = [];
        foreach (self::status() as $engine) {
            if (!$engine['available']) { $results[] = self::result($engine, 'unavailable', null, $engine['detail']); continue; }
            $results[] = $engine['name'] === 'Microsoft Defender' ? self::scanDefender($path, $engine) : self::scanClamav($path, $engine);
        }
        return $results;
    }

    private static function mode(): string { $mode = strtolower(mst_config()['scan_engines']); return in_array($mode, ['auto', 'defender', 'clamav', 'none'], true) ? $mode : 'auto'; }
    private static function timeout(): int { return max(10, min(600, (int)mst_config()['scan_timeout_seconds'])); }
    private static function result(array $engine, string $result, ?string $signature, string $detail): array { return ['name' => $engine['name'], 'version' => $engine['version'], 'signatureVersion' => $engine['signatureVersion'], 'result' => $result, 'signature' => $signature, 'detail' => FileRisk::cut($detail, 200)]; }

    // ---- Microsoft Defender -------------------------------------------------------------------------------

    private static function defenderPath(): ?string
    {
        $configured = mst_config()['defender_path'];
        if ($configured !== '') return is_file($configured) ? $configured : null;
        if (PHP_OS_FAMILY !== 'Windows') return null;
        // The newest platform folder holds the current MpCmdRun.exe; Program Files has the original one.
        $platform = glob((getenv('ProgramData') ?: 'C:\\ProgramData') . '\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe') ?: [];
        usort($platform, fn($a, $b) => version_compare(basename(dirname($b)), basename(dirname($a))));
        foreach ([...$platform, (getenv('ProgramFiles') ?: 'C:\\Program Files') . '\\Windows Defender\\MpCmdRun.exe'] as $candidate) if (is_file($candidate)) return $candidate;
        return null;
    }

    private static function defenderStatus(): array
    {
        $engine = ['name' => 'Microsoft Defender', 'available' => false, 'configured' => mst_config()['defender_path'] !== '' || self::mode() === 'defender', 'version' => null, 'signatureVersion' => null, 'detail' => ''];
        $path = self::defenderPath();
        if ($path === null) return ['detail' => PHP_OS_FAMILY === 'Windows' ? 'MpCmdRun.exe was not found' : 'Only available on Windows'] + $engine;
        $info = self::cached('defender', function () use ($path): array {
            [$code, $output] = self::run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', 'Get-MpComputerStatus | Select-Object AMProductVersion,AntivirusSignatureVersion,AntivirusEnabled | ConvertTo-Json -Compress'], 30);
            $json = $code === 0 ? json_decode(trim($output), true) : null;
            if (!is_array($json)) return ['version' => preg_match('#Platform\\\\([\d.]+)#', $path, $m) ? $m[1] : null, 'signatures' => null, 'enabled' => null];
            return ['version' => $json['AMProductVersion'] ?? null, 'signatures' => $json['AntivirusSignatureVersion'] ?? null, 'enabled' => $json['AntivirusEnabled'] ?? null];
        });
        if ($info['enabled'] === false) return ['detail' => 'Microsoft Defender Antivirus is turned off (another antivirus may be active)', 'version' => $info['version']] + $engine;
        return ['available' => true, 'version' => $info['version'], 'signatureVersion' => $info['signatures'], 'detail' => 'Ready', 'path' => $path] + $engine;
    }

    private static function scanDefender(string $path, array $engine): array
    {
        [$code, $output, $timedOut] = self::run([$engine['path'], '-Scan', '-ScanType', '3', '-File', $path, '-DisableRemediation'], self::timeout());
        if ($timedOut) return self::result($engine, 'error', null, 'Scan timed out after ' . self::timeout() . ' seconds');
        if (!is_file($path)) return self::result($engine, 'error', null, 'The file disappeared during the scan (real-time protection may have removed it)');
        if ($code === 2 || preg_match('/found\s+[1-9]\d*\s+threats?/i', $output)) {
            $signature = preg_match('/Threat\s*:\s*([^\r\n]+)/', $output, $match) ? trim($match[1]) : 'a threat';
            return self::result($engine, 'detected', FileRisk::cut($signature, 120), 'Signature match');
        }
        if ($code === 0) return self::result($engine, 'clean', null, 'No threats found');
        $reason = preg_match('/(failed with hr = 0x[0-9A-Fa-f]+|ERROR[^\r\n]*)/', $output, $match) ? $match[1] : "exit code $code";
        return self::result($engine, 'error', null, 'MpCmdRun could not scan the file (' . $reason . ')');
    }

    // ---- ClamAV ----------------------------------------------------------------------------------------

    private static function clamavPath(): ?string
    {
        $configured = mst_config()['clamav_path'];
        if ($configured !== '') return is_file($configured) ? $configured : null;
        $names = PHP_OS_FAMILY === 'Windows' ? ['clamdscan.exe', 'clamscan.exe'] : ['clamdscan', 'clamscan'];
        $folders = array_merge(explode(PATH_SEPARATOR, (string)getenv('PATH')), PHP_OS_FAMILY === 'Windows' ? [(getenv('ProgramFiles') ?: 'C:\\Program Files') . '\\ClamAV'] : ['/usr/bin', '/usr/local/bin']);
        // clamdscan (daemon) is much faster but only works when clamd is running; prefer clamscan unless configured.
        foreach (array_reverse($names) as $name) foreach ($folders as $folder) if ($folder !== '' && is_file($candidate = rtrim($folder, '\\/') . DIRECTORY_SEPARATOR . $name)) return $candidate;
        return null;
    }

    private static function clamavStatus(): array
    {
        $engine = ['name' => 'ClamAV', 'available' => false, 'configured' => mst_config()['clamav_path'] !== '' || self::mode() === 'clamav', 'version' => null, 'signatureVersion' => null, 'detail' => ''];
        $path = self::clamavPath();
        if ($path === null) return ['detail' => 'ClamAV is not installed (set CLAMAV_PATH in .env)'] + $engine;
        $info = self::cached('clamav', function () use ($path): array {
            [$code, $output] = self::run([$path, ...self::clamavDatabaseArgs(), '--version'], 30);
            // "ClamAV 1.4.1/27430/Mon Oct  7 08:35:46 2026" (engine / signature database version / date)
            return $code === 0 && preg_match('#ClamAV\s+([\d.]+)(?:/(\d+))?#', $output, $match) ? ['version' => $match[1], 'signatures' => $match[2] ?? null] : ['version' => null, 'signatures' => null];
        });
        if ($info['version'] === null) return ['detail' => 'ClamAV did not respond to --version'] + $engine;
        return ['available' => true, 'version' => $info['version'], 'signatureVersion' => $info['signatures'], 'detail' => 'Ready', 'path' => $path] + $engine;
    }

    private static function clamavDatabaseArgs(): array { $database = mst_config()['clamav_database']; return $database !== '' ? ['--database=' . $database] : []; }

    private static function scanClamav(string $path, array $engine): array
    {
        $daemon = str_contains(strtolower(basename($engine['path'])), 'clamdscan');
        $arguments = $daemon ? [$engine['path'], '--no-summary', '--fdpass', $path] : [$engine['path'], '--no-summary', '--stdout', ...self::clamavDatabaseArgs(), $path];
        [$code, $output, $timedOut] = self::run($arguments, self::timeout());
        if ($timedOut) return self::result($engine, 'error', null, 'Scan timed out after ' . self::timeout() . ' seconds');
        if ($code === 1 && preg_match('/:\s*(\S[^\r\n]*?)\s+FOUND/', $output, $match)) return self::result($engine, 'detected', FileRisk::cut($match[1], 120), 'Signature match');
        if ($code === 0) return self::result($engine, 'clean', null, 'No threats found');
        if (stripos($output, 'No supported database files found') !== false) return self::result($engine, 'unavailable', null, 'ClamAV has no virus signatures: run freshclam');
        return self::result($engine, 'error', null, 'ClamAV could not scan the file (exit code ' . $code . ')');
    }

    // ---- helpers ---------------------------------------------------------------------------------------

    /** Runs a program without a shell. Output goes to temporary files (pipes cannot be read without blocking on Windows). @return array{0: int, 1: string, 2: bool} [exit code, output, timed out] */
    private static function run(array $command, int $timeout): array
    {
        $outputFile = tempnam(sys_get_temp_dir(), 'mst');
        if ($outputFile === false) return [-1, 'no temporary file', false];
        $process = @proc_open($command, [0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'], 1 => ['file', $outputFile, 'w'], 2 => ['file', $outputFile, 'a']], $pipes, null, null, ['bypass_shell' => true]);
        if (!is_resource($process)) { @unlink($outputFile); return [-1, 'could not start', false]; }
        $started = microtime(true); $timedOut = false; $exitCode = -1;
        while (true) {
            $status = proc_get_status($process);
            if (!$status['running']) { $exitCode = $status['exitcode']; break; }
            if (microtime(true) - $started > $timeout) { $timedOut = true; proc_terminate($process); break; }
            usleep(50000);
        }
        $closed = proc_close($process);
        if ($exitCode === -1 && !$timedOut) $exitCode = $closed;
        $output = (string)@file_get_contents($outputFile, false, null, 0, 65536);
        @unlink($outputFile);
        return [$exitCode, $output, $timedOut];
    }

    // Engine versions change rarely; asking PowerShell/ClamAV on every scan would make each scan seconds slower.
    private static function cached(string $key, callable $load): array
    {
        $file = mst_storage_path('engine-' . $key . '.json');
        $cached = is_file($file) ? json_decode((string)@file_get_contents($file), true) : null;
        if (is_array($cached) && ($cached['at'] ?? 0) > time() - 3600) return $cached['data'];
        $data = $load();
        @file_put_contents($file, json_encode(['at' => time(), 'data' => $data]), LOCK_EX);
        return $data;
    }
}
