# MST File Scanner (Phase 13)

MST scans files with **real detection engines** and reports only what they actually found. Nothing on the scan
pages is simulated: no random percentages, no fake progress, no example results.

## Where scans happen

| Scan | Who / when | What checks the file |
|---|---|---|
| **Lab-PC scan** | Admin clicks *Scan* (Detected Files, Scan History) | The agent on that PC: antivirus engines + static analysis. The server adds VirusTotal (SHA-256 only) and the hash blocklist. |
| **Automatic scan** | Every new file in a watched folder, when *Settings → Scanner → Automatically scan new files* is on (at most 20 per PC per 10 minutes) | Same as above |
| **Upload scan** | Admin uploads a file on the **File Scanner** page | The MST server: its antivirus engines + static analysis + VirusTotal + blocklist |

Files are only **read** (hashed and inspected). They are never opened by another program, never run, and files on lab
PCs are never uploaded anywhere. Super Admin can view and export results but cannot scan, quarantine or investigate
(enforced by the API, not only by hidden buttons).

## Detection sources

| Source | What it gives | Notes |
|---|---|---|
| **Microsoft Defender** | Signature detection (e.g. `Virus:DOS/EICAR_Test_File`), engine + signature version | Built into Windows 10/11. Called as `MpCmdRun.exe -Scan -ScanType 3 -File … -DisableRemediation` (it reports only; MST decides about quarantine). Not available when another antivirus has turned Defender off. |
| **ClamAV** (optional) | Signature detection, engine + database version | Install from clamav.net, run `freshclam` once to download signatures. |
| **VirusTotal** | How many security vendors flag the SHA-256 | Free API key: 4 requests/minute, 500/day; MST stays within the limit and caches results for 24 h. An upload can optionally be **submitted** to VirusTotal (see the warning below). |
| **Hash blocklist** | Known-bad SHA-256 values (`hash_blocklist` table; the harmless EICAR test hash is included) | |
| **Static analysis** | Real file type from the content (“magic bytes”) and risk indicators | Double extensions (`grades.pdf.exe`), programs disguised as other files, type/extension mismatch, Office macros, PDF JavaScript/Launch, RTF embedded objects, programs inside ZIP files, password-protected archives, suspicious script commands (encoded PowerShell, download-and-run). |

## Risk levels

The rules live in `backend/helpers/ScanClassifier.php`.

| Risk level | When |
|---|---|
| **High** | An antivirus engine detected the file, **or** it matches the blocklist, **or** 3+ VirusTotal vendors flag it, **or** it is a disguised program / double extension |
| **Medium** | 1–2 VirusTotal vendors (or “suspicious” votes), **or** a suspicious indicator (macros, active PDF content, programs inside an archive, password-protected archive, suspicious script commands, type mismatch) |
| **Safe** | Nothing Medium/High was found **and** at least one engine actually checked the file and found nothing (Defender/ClamAV clean, or VirusTotal with 0 detections from 10+ vendors). *Safe means the configured scanners found no threat; it does not guarantee the file is completely safe.* |
| **Unknown** | No engine could check the file (no antivirus available, VirusTotal not configured or never saw the file) and nothing suspicious was found |
| **Failed** | The scan could not complete (file missing or locked, moved out of the watch folders, timeout) |

A file is never called Safe just because no signature was found: if no engine could check it, the result is **Unknown**.

### Confidence → "Evidence strength"

The engines do not give calibrated probabilities, and VirusTotal vendor counts are **not** a probability that a file
is malicious. MST therefore shows a labelled **evidence strength**, kept separate from the risk level:

| Strength | Meaning |
|---|---|
| **Strong** | Antivirus signature match, blocklist match, 10+ VirusTotal vendors, or (for Safe) two independent clean results, e.g. Defender **and** VirusTotal |
| **Moderate** | 3–9 VirusTotal vendors, a disguised program, or (for Safe) one clean engine result |
| **Limited** | Only suspicious indicators, or 1–2 VirusTotal vendors |
| **N/A** | Not enough evidence (Unknown, Failed) |

**Partial analysis** is shown when at least one source could not check the file (for example VirusTotal was rate-limited).
Every report lists the evidence behind its result, the scanners with their versions, and recommended next steps.

## Scan History and actions

Columns: Scan ID, File Name, Computer, SHA-256, Risk Level, Detection, Confidence (evidence strength), Scan Date,
Scanner, Status (Pending / Scanning / Completed / Failed), Action. It supports search, filters (risk, status, computer,
source, date range), sorting and paging.

| Action | Who | What really happens (and is recorded in Activity Logs) |
|---|---|---|
| View Details | both | Full report: metadata, engines, VirusTotal, evidence, recommendations |
| Export Report / Export CSV | both | Text report / CSV built from the database records |
| View on Computer | both | Opens that computer's details and recent file activity |
| Investigate | Admin | Marks the linked threat *Investigating* and shows copies of the same file elsewhere and file activity around the scan |
| Scan Again | Admin | New scan job for the agent, or a new scan of the stored upload |
| Quarantine | Admin, with confirmation | The agent moves the file into its quarantine folder, after verifying its SHA-256 |
| Release from Quarantine | Admin, with a written reason and typing `RELEASE` | Refused when the latest scan is High; the agent verifies the hash and restores the file |
| Delete | Admin, typing `DELETE` | **Retention policy:** a file on a lab PC can only be deleted after it was quarantined. An uploaded copy is deleted automatically after the retention period (default 7 days) or earlier by the Admin. Scan records are never deleted. |

## Setup

### 1. Database (once)
Run `database/migrations/phase13_scanner.sql` in MySQL Workbench (after `phase12_security.sql`).

### 2. PHP upload limit (MST server)
PHP accepts only 2 MB uploads by default. Open your `php.ini` (`php --ini` shows where it is) and set:
```ini
upload_max_filesize = 32M
post_max_size = 40M
```
Restart the API terminal. The File Scanner page shows the real maximum size.

### 3. VirusTotal key (optional, recommended)
Add `VIRUSTOTAL_API_KEY=your-key` to `.env` and restart the API. Without a key, scans still work; VirusTotal shows
*Not configured*. Never commit `.env`.

> **Upload to VirusTotal** (checkbox on the File Scanner page) sends the whole file to VirusTotal, which shares it with
> security vendors. Do not use it for confidential files (grades, personal data). Without it, only the SHA-256 is sent.

### 4. Antivirus engines
- **Lab PCs:** nothing to install when Microsoft Defender is on. The agent log shows
  `Antivirus engine: Microsoft Defender … - Ready` at start-up.
- **MST server** (for uploads): Defender is found automatically on Windows. Optional: install ClamAV and set
  `CLAMAV_PATH` in `.env` (or `clamav_path` in the agent's `config.json`).
- `SCAN_ENGINES` / `"antivirus"`: `auto` (all installed), `defender`, `clamav`, `none`.

### 5. Agent update (each lab PC)
Copy the new `agent` folder and restart `python run_agent.py`. New `config.json` keys (all optional): `antivirus`,
`clamav_path`, `scan_timeout_seconds`, `quarantine_folder` (see `agent/config.example.json`).

## Testing safely (EICAR)

Never use real malware. The **EICAR test file** is a harmless text file that every antivirus detects on purpose.

- Windows Defender removes EICAR as soon as it is written, so for a demo create a folder that Defender ignores:
  *Windows Security → Virus & threat protection → Manage settings → Exclusions → Add a folder* (e.g. `C:\MST-Test`),
  add it to the agent's `watch_folders`, and save the EICAR text there. Remove the exclusion after the demo.
  Defender usually skips excluded folders in its own scans too, so in this demo the **High** result comes from the
  hash blocklist and VirusTotal (and ClamAV if installed); the report shows which source detected it.
- Without the exclusion, Defender deleting the file is itself the real behaviour: the dashboard shows the file as
  created and then deleted.

Other harmless tests: rename a copy of `notepad.exe` to `photo.jpg` (disguised program → High), name a file
`grades.pdf.exe` (double extension → High), save a Word document with a macro as `.docm` (→ Medium).

## Known limitations

- Download source information exists only on Windows and only when the browser records it (Mark of the Web).
- A free VirusTotal key allows 4 requests per minute; bursts of new files may show *Partial analysis*. Use **Scan Again** later.
- PHP's built-in server handles one request at a time, so a long upload scan briefly delays other pages.
- The server's own real-time antivirus may remove a malicious upload before MST scans it; the scan then reports **Failed** with that explanation.
