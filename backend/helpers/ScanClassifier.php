<?php
declare(strict_types=1);

require_once __DIR__ . '/FileRisk.php';

/**
 * Turns the evidence collected by a scan into the MST risk level. Documented in SCANNER.md.
 *
 * Evidence sources: antivirus engines (Microsoft Defender / ClamAV: a signature match is a confirmed detection),
 * VirusTotal hash reputation (how many security vendors flag the file), the MST hash blocklist, and static
 * indicators (FileAnalyzer / agent analysis.py).
 *
 * Risk level (what the evidence says)          Evidence strength (how much evidence supports it, NOT a probability)
 *   High    - an antivirus engine detected it, blocklist match, VirusTotal >= 3 vendors, or a disguised program
 *   Medium  - VirusTotal 1-2 vendors / suspicious votes, or a suspicious indicator (macros, active PDF, ...)
 *   Safe    - no Medium/High evidence AND at least one engine actually checked the file and found nothing
 *   Unknown - no engine could check the file and nothing suspicious was found
 *   Failed  - the scan itself could not be completed
 */
final class ScanClassifier
{
    public const RISKS = ['Safe', 'Medium', 'High', 'Unknown', 'Failed'];
    public const STRENGTHS = ['Strong', 'Moderate', 'Limited', 'N/A'];
    public const LEGACY_STATUS = ['High' => 'THREAT', 'Medium' => 'WARNING', 'Safe' => 'SAFE', 'Unknown' => 'UNKNOWN', 'Failed' => 'FAILED'];
    private const STRENGTH_RANK = ['N/A' => 0, 'Limited' => 1, 'Moderate' => 2, 'Strong' => 3];
    private const VT_MIN_ENGINES_FOR_CLEAN = 10;

    /**
     * @param array{engines?: array, virusTotal?: ?array, indicators?: array, blocklist?: ?array, error?: ?string, hashAvailable?: bool} $evidence
     * @return array{risk: string, status: string, detection: string, strength: string, coverage: ?string, threatCount: int, threatSeverity: ?string, factors: string[], recommendations: string[], scanner: string}
     */
    public static function classify(array $evidence): array
    {
        $scanner = self::scannerLabel($evidence);
        if (!empty($evidence['error'])) {
            return ['risk' => 'Failed', 'status' => 'FAILED', 'detection' => FileRisk::cut((string)$evidence['error'], 255), 'strength' => 'N/A', 'coverage' => null, 'threatCount' => 0, 'threatSeverity' => null,
                'factors' => ['The scan could not be completed: ' . $evidence['error']], 'recommendations' => self::recommendations('Failed'), 'scanner' => $scanner];
        }
        $high = []; $medium = []; $clean = []; $gaps = []; $factors = [];
        foreach ($evidence['engines'] ?? [] as $engine) {
            $name = $engine['name'] . (!empty($engine['version']) ? ' ' . $engine['version'] : '');
            $result = $engine['result'] ?? 'error';
            if ($result === 'detected') { $high[] = ['Strong', "{$engine['name']} detected " . ($engine['signature'] ?: 'a threat')]; $factors[] = "$name: detected " . ($engine['signature'] ?: 'a threat') . ' (signature match)'; }
            elseif ($result === 'clean') { $clean[] = $engine['name']; $factors[] = "$name: no threat found"; }
            else { $gaps[] = $engine['name']; $factors[] = "$name: " . ($engine['detail'] ?: 'could not scan the file'); }
        }
        if (!empty($evidence['blocklist'])) { $high[] = ['Strong', 'Matches the MST blocklist: ' . $evidence['blocklist']['name']]; $factors[] = 'SHA-256 matches the MST hash blocklist entry "' . $evidence['blocklist']['name'] . '"'; }

        $vt = $evidence['virusTotal'] ?? null;
        $vtStatus = $vt['status'] ?? 'not_checked';
        if ($vtStatus === 'found') {
            $malicious = (int)$vt['malicious']; $suspicious = (int)($vt['suspicious'] ?? 0); $total = (int)$vt['total'];
            $text = "VirusTotal: $malicious of $total security vendors flagged it" . ($suspicious ? " ($suspicious more marked it suspicious)" : '');
            $factors[] = $text;
            if ($malicious >= 10) $high[] = ['Strong', "$malicious/$total VirusTotal vendors flagged it"];
            elseif ($malicious >= 3) $high[] = ['Moderate', "$malicious/$total VirusTotal vendors flagged it"];
            elseif ($malicious >= 1 || $suspicious >= 1) $medium[] = ['Limited', "$malicious/$total VirusTotal vendors flagged it" . ($suspicious ? ", $suspicious suspicious" : '')];
            elseif ($total >= self::VT_MIN_ENGINES_FOR_CLEAN) $clean[] = "VirusTotal ($total engines)";
            else $gaps[] = 'VirusTotal';
        } elseif ($vtStatus === 'not_found') {
            $factors[] = 'VirusTotal: this file has never been submitted to VirusTotal (no reputation available)';
        } elseif ($vtStatus === 'pending') {
            $gaps[] = 'VirusTotal'; $factors[] = 'VirusTotal: the file was uploaded and is still being analysed';
        } elseif ($vtStatus !== 'not_checked') {
            $gaps[] = 'VirusTotal'; $factors[] = 'VirusTotal: ' . ($vtStatus === 'not_configured' ? 'not configured' : ($vt['reason'] ?? 'unavailable'));
        }

        foreach ($evidence['indicators'] ?? [] as $indicator) {
            $text = $indicator['title'] . ($indicator['detail'] !== '' ? ': ' . $indicator['detail'] : '');
            if ($indicator['severity'] === 'HIGH' || $indicator['severity'] === 'CRITICAL') $high[] = ['Moderate', $text];
            elseif ($indicator['severity'] === 'MEDIUM') $medium[] = ['Limited', $text];
            $factors[] = 'Static analysis (' . $indicator['severity'] . '): ' . $text;
        }
        foreach ($evidence['notes'] ?? [] as $note) $factors[] = $note;
        if (($evidence['hashAvailable'] ?? true) === false) { $gaps[] = 'SHA-256'; $factors[] = 'No SHA-256 (file larger than the hashing limit), so hash reputation was not checked'; }

        if ($high) { [$strength, $detection] = self::strongest($high); $risk = 'High'; }
        elseif ($medium) { [$strength, $detection] = self::strongest($medium); $risk = 'Medium'; }
        elseif ($clean) { $risk = 'Safe'; $strength = count($clean) >= 2 ? 'Strong' : 'Moderate'; $detection = 'No threat detected by ' . implode(' and ', $clean); }
        else { $risk = 'Unknown'; $strength = 'N/A'; $detection = 'No antivirus engine or reputation service could check this file'; }

        $threats = count($high);
        return [
            'risk' => $risk,
            'status' => self::LEGACY_STATUS[$risk],
            'detection' => FileRisk::cut($detection, 255),
            'strength' => $strength,
            'coverage' => $gaps ? 'Partial' : 'Full',
            'threatCount' => $threats,
            'threatSeverity' => $risk === 'High' ? ($strength === 'Strong' ? 'CRITICAL' : 'HIGH') : null,
            'factors' => $factors,
            'recommendations' => self::recommendations($risk),
            'scanner' => $scanner,
        ];
    }

    /** @param array<int, array{0: string, 1: string}> $items */
    private static function strongest(array $items): array
    {
        usort($items, fn($a, $b) => self::STRENGTH_RANK[$b[0]] <=> self::STRENGTH_RANK[$a[0]]);
        return $items[0];
    }

    // "Microsoft Defender 4.18 (signatures 1.4) · ClamAV 1.4 · VirusTotal API v3 · MST static analysis 1.0"
    public static function scannerLabel(array $evidence): string
    {
        $parts = [];
        foreach ($evidence['engines'] ?? [] as $engine) $parts[] = trim($engine['name'] . ' ' . ($engine['version'] ?? '') . (!empty($engine['signatureVersion']) ? ' (signatures ' . $engine['signatureVersion'] . ')' : ''));
        $vt = $evidence['virusTotal']['status'] ?? null;
        if (in_array($vt, ['found', 'not_found', 'pending'], true)) $parts[] = 'VirusTotal API v3';
        if (array_key_exists('indicators', $evidence)) $parts[] = 'MST static analysis ' . ($evidence['analyzerVersion'] ?? '1.0');
        return FileRisk::cut(implode(' · ', $parts) ?: 'None', 255);
    }

    public static function recommendations(string $risk): array
    {
        return match ($risk) {
            'High' => ['Do not open or run the file.', 'Quarantine it on the computer (Quarantine action), or ask the user to delete it.', 'Search Scan History for the same SHA-256 to find copies on other computers.', 'Review the computer\'s recent file activity and the source of the file (download information).', 'After the investigation, delete the quarantined file and mark the threat Resolved.'],
            'Medium' => ['Do not run or enable content (macros, scripts) in the file until it has been reviewed.', 'Ask the user where the file came from and whether it is expected.', 'Scan Again later: VirusTotal and antivirus signatures are updated continuously.', 'Quarantine the file if its origin cannot be confirmed.'],
            'Unknown' => ['Treat the file as untrusted: no antivirus engine was able to check it.', 'Make sure Microsoft Defender or ClamAV is available on the computer and/or add a VirusTotal API key, then Scan Again.'],
            'Failed' => ['Check that the file still exists and that the computer\'s agent is online, then Scan Again.'],
            default => ['No action needed. A Safe result means the configured scanners found no threat; it does not guarantee the file is completely safe.'],
        };
    }
}
