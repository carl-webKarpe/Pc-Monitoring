<?php
declare(strict_types=1);

// Risk and sensitivity rules for files reported by the lab-PC agents.
// Pre-scan values come from the file name only; the on-PC scan (agent) plus the hash blocklist give the final result.
final class FileRisk
{
    public const RISK_LEVELS = ['Unknown', 'Safe', 'Low', 'Medium', 'High', 'Critical'];
    public const CLASSIFICATIONS = ['Normal', 'Confidential'];
    public const EXECUTABLE_EXTENSIONS = ['exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'pif', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta', 'jar', 'dll', 'cpl', 'reg'];
    public const DOCUMENT_EXTENSIONS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'mp3', 'mp4', 'avi', 'zip', 'rar'];
    // Words in a file name or folder that suggest the file may hold sensitive school/personal data.
    public const CONFIDENTIAL_KEYWORDS = ['confidential', 'private', 'secret', 'payroll', 'salary', 'password', 'passwd', 'credential', 'grades', 'gradesheet', 'grade_sheet', 'exam', 'answer key', 'answer_key', 'answerkey', 'bank', 'contract', 'passport', 'id card', 'id_card', 'tax'];

    // Agent finding rules the server accepts, with the highest severity each may carry.
    public const AGENT_RULES = [
        'double_extension' => ['Double file extension', 'HIGH'],
        'disguised_executable' => ['Disguised executable', 'HIGH'],
        'executable_from_internet' => ['Executable downloaded from the internet', 'MEDIUM'],
        'executable_type' => ['Executable or script file', 'LOW'],
        'internet_download' => ['Downloaded from the internet', 'INFO'],
        'hash_changed' => ['File changed since it was detected', 'INFO'],
    ];
    private const SEVERITY_RANK = ['INFO' => 0, 'LOW' => 1, 'MEDIUM' => 2, 'HIGH' => 3, 'CRITICAL' => 4];
    private const RISK_BY_RANK = ['Safe', 'Low', 'Medium', 'High', 'Critical'];

    /** Cuts text to at most $maxChars characters without breaking a multi-byte (UTF-8) character. */
    public static function cut(string $text, int $maxChars): string { return preg_match('/^.{0,' . $maxChars . '}/us', $text, $match) ? $match[0] : ''; }

    private static function extensions(string $fileName): array { $parts = explode('.', strtolower($fileName)); array_shift($parts); return $parts; }

    public static function hasDoubleExtension(string $fileName): bool
    {
        $parts = self::extensions($fileName);
        return count($parts) >= 2 && in_array($parts[count($parts) - 2], self::DOCUMENT_EXTENSIONS, true) && in_array($parts[count($parts) - 1], self::EXECUTABLE_EXTENSIONS, true);
    }

    public static function isExecutable(string $fileName): bool { $parts = self::extensions($fileName); return $parts !== [] && in_array(end($parts), self::EXECUTABLE_EXTENSIONS, true); }

    // Before a scan: judged from the name only. Unknown means "not scanned yet".
    public static function preScanRisk(string $fileName): string
    {
        if (self::hasDoubleExtension($fileName)) return 'High';
        return self::isExecutable($fileName) ? 'Low' : 'Unknown';
    }

    public static function suggestConfidential(string $fileName, string $filePath): bool
    {
        $text = strtolower($filePath . ' ' . $fileName);
        foreach (self::CONFIDENTIAL_KEYWORDS as $keyword) if (str_contains($text, $keyword)) return true;
        return false;
    }

    /**
     * Combines agent findings with a hash-blocklist match into the final scan verdict.
     * @param array<int, array{rule: string, severity: string, detail: string}> $findings
     * @return array{status: string, risk: string, threatCount: int, findings: array, top: ?array}
     */
    public static function verdict(array $findings, ?array $blocklistMatch): array
    {
        if ($blocklistMatch) array_unshift($findings, ['rule' => 'known_malicious_hash', 'title' => 'Known malicious file', 'severity' => $blocklistMatch['severity'], 'detail' => 'SHA-256 matches the blocklist entry "' . $blocklistMatch['name'] . '"']);
        $rank = 0; $top = null; $threats = 0;
        foreach ($findings as $finding) {
            $findingRank = self::SEVERITY_RANK[$finding['severity']] ?? 0;
            if ($findingRank >= 3) $threats++;
            if ($findingRank > $rank) { $rank = $findingRank; $top = $finding; }
        }
        return ['status' => $rank >= 3 ? 'THREAT' : ($rank === 2 ? 'WARNING' : 'SAFE'), 'risk' => self::RISK_BY_RANK[$rank], 'threatCount' => $threats, 'findings' => $findings, 'top' => $top];
    }

    /** Validates findings sent by an agent: known rules only, severity capped at the rule's maximum. */
    public static function cleanFindings(mixed $findings): array
    {
        if (!is_array($findings)) return [];
        $clean = [];
        foreach (array_slice($findings, 0, 20) as $finding) {
            if (!is_array($finding) || !isset(self::AGENT_RULES[$finding['rule'] ?? ''])) continue;
            [$title, $maxSeverity] = self::AGENT_RULES[$finding['rule']];
            $severity = is_string($finding['severity'] ?? null) && isset(self::SEVERITY_RANK[$finding['severity']]) ? $finding['severity'] : $maxSeverity;
            if (self::SEVERITY_RANK[$severity] > self::SEVERITY_RANK[$maxSeverity]) $severity = $maxSeverity;
            $detail = is_string($finding['detail'] ?? null) && preg_match('/^.{0,200}/us', preg_replace('/[\x00-\x1F\x7F<>]/', '', $finding['detail']) ?? '', $match) ? $match[0] : '';
            $clean[] = ['rule' => $finding['rule'], 'title' => $title, 'severity' => $severity, 'detail' => $detail];
        }
        return $clean;
    }
}
