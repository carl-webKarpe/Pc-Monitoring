<?php
declare(strict_types=1);

require_once __DIR__ . '/FileRisk.php';

// Static (non-executing) analysis of a file on the MST server: real file type from its content ("magic bytes"),
// and structural risk indicators (disguised programs, Office macros, active PDF content, archives with programs).
// The same rules run in the lab-PC agent (agent/mst_agent/analysis.py). Files are only read, never opened or run.
final class FileAnalyzer
{
    public const VERSION = '1.0';
    private const CONTENT_SCAN_BYTES = 16 * 1024 * 1024; // indicators are searched in the first 16 MB

    // family => [label, extensions that are normal for it]
    public const FAMILIES = [
        'pe' => ['Windows program (PE)', ['exe', 'dll', 'sys', 'scr', 'com', 'cpl', 'ocx', 'drv', 'efi', 'mui', 'ax', 'pyd', 'node', 'msstyles', 'winmd']],
        'elf' => ['Linux program (ELF)', ['', 'so', 'bin', 'elf', 'run', 'o']],
        'macho' => ['macOS program (Mach-O)', ['', 'dylib', 'bundle', 'so']],
        'pdf' => ['PDF document', ['pdf']],
        'ooxml' => ['Microsoft Office document (OOXML)', ['docx', 'docm', 'dotx', 'dotm', 'xlsx', 'xlsm', 'xltx', 'xltm', 'xlam', 'pptx', 'pptm', 'ppsx', 'ppsm', 'potx', 'vsdx', 'zip']],
        'zip' => ['ZIP archive', ['zip', 'jar', 'apk', 'odt', 'ods', 'odp', 'epub', 'xpi', 'nupkg', 'msix', 'appx', 'whl', 'kmz', 'docx', 'xlsx', 'pptx', '3mf', 'crx']],
        'ole' => ['Microsoft Office 97-2003 / Installer (OLE)', ['doc', 'dot', 'xls', 'xlt', 'xla', 'ppt', 'pps', 'pot', 'msi', 'msp', 'msg', 'vsd', 'pub', 'mpp', 'ole']],
        'rar' => ['RAR archive', ['rar']],
        '7z' => ['7-Zip archive', ['7z']],
        'gzip' => ['GZIP archive', ['gz', 'tgz']],
        'cab' => ['Windows cabinet archive', ['cab', 'msu']],
        'iso' => ['Disk image (ISO)', ['iso', 'img']],
        'png' => ['PNG image', ['png']],
        'jpeg' => ['JPEG image', ['jpg', 'jpeg', 'jpe', 'jfif']],
        'gif' => ['GIF image', ['gif']],
        'bmp' => ['BMP image', ['bmp', 'dib']],
        'webp' => ['WebP image', ['webp']],
        'ico' => ['Icon image', ['ico', 'cur']],
        'mp3' => ['MP3 audio', ['mp3']],
        'mp4' => ['MP4/MOV video', ['mp4', 'm4a', 'm4v', 'mov', '3gp', 'heic', 'heif', 'avif']],
        'riff' => ['RIFF media (AVI/WAV)', ['avi', 'wav']],
        'rtf' => ['Rich Text document', ['rtf', 'doc']],
        'lnk' => ['Windows shortcut (LNK)', ['lnk']],
        'html' => ['HTML document', ['html', 'htm', 'hta', 'xhtml', 'mht', 'svg']],
        'script' => ['Script (text)', ['ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta', 'sh', 'py', 'pl', 'rb', 'php', 'reg']],
        'text' => ['Text', ['txt', 'csv', 'log', 'md', 'json', 'xml', 'ini', 'cfg', 'conf', 'yml', 'yaml', 'html', 'htm', 'css', 'js', 'ps1', 'bat', 'cmd', 'vbs', 'py', 'sql', 'reg', 'svg', 'tsv', 'srt', 'c', 'h', 'cpp', 'java', 'cs', 'php', 'sh', 'inf', 'nfo', 'rtf']],
        'empty' => ['Empty file', []],
        'unknown' => ['Unrecognized binary data', []],
    ];
    // Formats without a recognizable header (e.g. DOS .com programs): their content cannot contradict the extension.
    private const HEADERLESS_EXTENSIONS = ['com', 'bin', 'dat'];
    private const SCRIPT_EXTENSIONS = ['ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta', 'sh', 'reg'];
    // Patterns often used by malicious scripts to hide code or download and run more code.
    private const SCRIPT_PATTERNS = [
        '/-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/i' => 'encoded PowerShell command',
        '/FromBase64String/i' => 'Base64 decoding',
        '/DownloadString|DownloadFile|Invoke-WebRequest|\biwr\s+http|Net\.WebClient|Start-BitsTransfer|bitsadmin\s+\/transfer/i' => 'downloads content from the internet',
        '/Invoke-Expression|\biex\s*[\(\$]/i' => 'runs generated code (Invoke-Expression)',
        '/certutil(\.exe)?\s+[^\r\n]*-(urlcache|decode)/i' => 'certutil download/decode',
        '/WScript\.Shell|Shell\.Application|CreateObject\(\s*"(WScript|Shell)/i' => 'starts other programs (WScript.Shell)',
        '/mshta(\.exe)?\s+(http|vbscript|javascript)/i' => 'mshta remote script',
        '/-w(indowstyle)?\s+hidden/i' => 'hidden window',
    ];

    /** @return array{family: string, label: string, extension: string, extensionMatches: bool} */
    public static function identify(string $path, string $fileName): array
    {
        $extension = self::extension($fileName);
        $size = @filesize($path);
        $handle = @fopen($path, 'rb');
        $head = $handle ? (string)fread($handle, 65536) : '';
        $isoMarker = '';
        if ($handle && $size !== false && $size > 0x8006) { fseek($handle, 0x8001); $isoMarker = (string)fread($handle, 5); }
        if ($handle) fclose($handle);
        $family = $size === 0 ? 'empty' : self::familyOf($head, $isoMarker, $path);
        [$label, $extensions] = self::FAMILIES[$family];
        $matches = in_array($extension, self::HEADERLESS_EXTENSIONS, true) || match ($family) {
            'unknown', 'empty' => true,
            'text' => $extension === '' || in_array($extension, self::FAMILIES['text'][1], true) || in_array($extension, self::SCRIPT_EXTENSIONS, true),
            default => in_array($extension, $extensions, true),
        };
        return ['family' => $family, 'label' => $label, 'extension' => $extension, 'extensionMatches' => $matches];
    }

    /** @return array<int, array{rule: string, title: string, severity: string, detail: string}> */
    public static function indicators(string $path, string $fileName, array $type): array
    {
        $found = [];
        $add = static function (string $rule, string $severity, string $detail) use (&$found): void { $found[] = ['rule' => $rule, 'title' => FileRisk::AGENT_RULES[$rule][0] ?? $rule, 'severity' => $severity, 'detail' => FileRisk::cut($detail, 200)]; };
        $extension = $type['extension'];
        $executableFamily = in_array($type['family'], ['pe', 'elf', 'macho'], true);

        if (FileRisk::hasDoubleExtension($fileName)) $add('double_extension', 'HIGH', "'$fileName' pretends to be a document but ends in .$extension");
        if ($executableFamily && !$type['extensionMatches']) $add('disguised_executable', 'HIGH', "The content is a {$type['label']} but the extension is '." . ($extension ?: 'none') . "'");
        elseif (!$type['extensionMatches']) $add('type_mismatch', 'MEDIUM', "The content is a {$type['label']} but the extension is '." . ($extension ?: 'none') . "'");

        $content = self::readContent($path);
        if ($type['family'] === 'ooxml' || $type['family'] === 'zip') {
            $entries = self::zipEntries($path);
            if ($entries['vba']) $add('office_macros', 'MEDIUM', 'The document contains VBA macros (vbaProject.bin)');
            if ($entries['executables']) $add('archive_executable', 'MEDIUM', 'The archive contains program/script files: ' . implode(', ', array_slice($entries['executables'], 0, 5)));
            if ($entries['encrypted']) $add('encrypted_archive', 'MEDIUM', 'The archive is password-protected, so its contents cannot be inspected');
        }
        if ($type['family'] === 'ole' && (str_contains($content, "_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0") || str_contains($content, 'Attribute VB_'))) $add('office_macros', 'MEDIUM', 'The document contains VBA macros');
        if ($type['family'] === 'rtf' && preg_match('/\\\\objdata|\\\\objupdate/i', $content)) $add('rtf_embedded_object', 'MEDIUM', 'The RTF document contains embedded objects (often used by document exploits)');
        if ($type['family'] === 'pdf') {
            $active = [];
            if (preg_match('/\/(JavaScript|JS)[\s\/\(<\[]/', $content)) $active[] = 'JavaScript';
            if (preg_match('/\/Launch[\s\/<]/', $content)) $active[] = 'Launch action (can start programs)';
            if ($active) $add('pdf_active_content', 'MEDIUM', 'The PDF contains ' . implode(' and ', $active));
            if (preg_match('/\/EmbeddedFile[\s\/<]/', $content)) $add('pdf_embedded_file', 'LOW', 'The PDF contains embedded files');
        }
        if (in_array($extension, self::SCRIPT_EXTENSIONS, true) || $type['family'] === 'script') {
            $hits = [];
            foreach (self::SCRIPT_PATTERNS as $pattern => $label) if (preg_match($pattern, $content)) $hits[] = $label;
            if ($hits) $add('suspicious_script', 'MEDIUM', 'Script ' . implode(', ', array_slice($hits, 0, 4)));
        }
        if ($type['family'] === 'lnk') $add('shortcut_file', 'LOW', 'Windows shortcut file: check which program it starts');
        if (($executableFamily || in_array($extension, FileRisk::EXECUTABLE_EXTENSIONS, true)) && !array_filter($found, fn($f) => $f['severity'] === 'HIGH')) $add('executable_type', 'LOW', 'Program or script file (' . ($type['label']) . ')');
        return $found;
    }

    private static function extension(string $fileName): string { $dot = strrpos($fileName, '.'); return $dot === false ? '' : strtolower(substr($fileName, $dot + 1)); }

    private static function familyOf(string $head, string $isoMarker, string $path): string
    {
        $starts = static fn(string $magic): bool => str_starts_with($head, $magic);
        if ($starts('MZ')) return 'pe';
        if ($starts("\x7FELF")) return 'elf';
        if (in_array(substr($head, 0, 4), ["\xFE\xED\xFA\xCE", "\xCE\xFA\xED\xFE", "\xFE\xED\xFA\xCF", "\xCF\xFA\xED\xFE"], true)) return 'macho';
        if (str_contains(substr($head, 0, 1024), '%PDF-')) return 'pdf';
        if ($starts("PK\x03\x04") || $starts("PK\x05\x06")) {
            $entries = self::zipEntries($path);
            return $entries['ooxml'] ? 'ooxml' : 'zip';
        }
        if ($starts("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) return 'ole';
        if ($starts("Rar!\x1A\x07")) return 'rar';
        if ($starts("7z\xBC\xAF\x27\x1C")) return '7z';
        if ($starts("\x1F\x8B")) return 'gzip';
        if ($starts('MSCF')) return 'cab';
        if ($isoMarker === 'CD001') return 'iso';
        if ($starts("\x89PNG\r\n\x1A\n")) return 'png';
        if ($starts("\xFF\xD8\xFF")) return 'jpeg';
        if ($starts('GIF87a') || $starts('GIF89a')) return 'gif';
        if ($starts('BM') && strlen($head) > 14 && unpack('V', substr($head, 2, 4))[1] > 14) return 'bmp';
        if ($starts('RIFF') && substr($head, 8, 4) === 'WEBP') return 'webp';
        if ($starts('RIFF') && in_array(substr($head, 8, 4), ['AVI ', 'WAVE'], true)) return 'riff';
        if ($starts("\x00\x00\x01\x00") && strlen($head) > 6) return 'ico';
        if ($starts('ID3') || $starts("\xFF\xFB") || $starts("\xFF\xF3")) return 'mp3';
        if (substr($head, 4, 4) === 'ftyp') return 'mp4';
        if ($starts('{\\rtf')) return 'rtf';
        if ($starts("\x4C\x00\x00\x00\x01\x14\x02\x00")) return 'lnk';
        $text = ltrim(preg_replace('/^\xEF\xBB\xBF/', '', $head) ?? '');
        if (self::looksLikeText($head)) {
            if (preg_match('/^(<!doctype html|<html|<hta:application)/i', $text)) return 'html';
            if (str_starts_with($text, '#!')) return 'script';
            return 'text';
        }
        return 'unknown';
    }

    private static function looksLikeText(string $head): bool
    {
        if ($head === '') return false;
        $sample = substr($head, 0, 8192);
        if (str_starts_with($sample, "\xFF\xFE") || str_starts_with($sample, "\xFE\xFF")) return true; // UTF-16 text
        if (str_contains($sample, "\0")) return false;
        $control = preg_match_all('/[\x00-\x08\x0E-\x1A\x1C-\x1F\x7F]/', $sample);
        return $control <= strlen($sample) * 0.02;
    }

    private static function readContent(string $path): string
    {
        $content = @file_get_contents($path, false, null, 0, self::CONTENT_SCAN_BYTES);
        return $content === false ? '' : $content;
    }

    /**
     * Lists a ZIP's central directory without extracting anything.
     * @return array{ooxml: bool, vba: bool, encrypted: bool, executables: string[]}
     */
    public static function zipEntries(string $path): array
    {
        $result = ['ooxml' => false, 'vba' => false, 'encrypted' => false, 'executables' => []];
        $size = @filesize($path);
        $handle = @fopen($path, 'rb');
        if (!$handle || !$size) return $result;
        $tailLength = min($size, 65557);
        fseek($handle, $size - $tailLength);
        $tail = (string)fread($handle, $tailLength);
        $end = strrpos($tail, "PK\x05\x06");
        if ($end === false || strlen($tail) < $end + 22) { fclose($handle); return $result; }
        $record = unpack('vdisk/vcdDisk/ventriesHere/ventries/VcdSize/VcdOffset', substr($tail, $end + 4, 16));
        if ($record['cdOffset'] + $record['cdSize'] > $size || $record['cdSize'] > 16 * 1024 * 1024) { fclose($handle); return $result; }
        fseek($handle, $record['cdOffset']);
        $directory = (string)fread($handle, $record['cdSize']);
        fclose($handle);
        $offset = 0; $count = 0;
        while ($count++ < 20000 && $offset + 46 <= strlen($directory) && substr($directory, $offset, 4) === "PK\x01\x02") {
            $entry = unpack('vflags', substr($directory, $offset + 8, 2)) + unpack('vnameLength/vextraLength/vcommentLength', substr($directory, $offset + 28, 6));
            $name = substr($directory, $offset + 46, $entry['nameLength']);
            $lower = strtolower($name);
            if ($lower === '[content_types].xml') $result['ooxml'] = true;
            if (str_ends_with($lower, 'vbaproject.bin')) $result['vba'] = true;
            if (($entry['flags'] & 1) === 1) $result['encrypted'] = true;
            $extension = ($dot = strrpos($lower, '.')) === false ? '' : substr($lower, $dot + 1);
            if (in_array($extension, FileRisk::EXECUTABLE_EXTENSIONS, true) && count($result['executables']) < 20) $result['executables'][] = basename(str_replace('\\', '/', $name));
            $offset += 46 + $entry['nameLength'] + $entry['extraLength'] + $entry['commentLength'];
        }
        return $result;
    }
}
