# MST PHP API

Phase 7 connects the PHP REST API to MySQL (`mst_database`) through PDO, with PHP sessions and server-side RBAC. Computer, threat and scan records in the database are **demonstration data**; there is no Python Agent, LAN monitoring, real scanner, VirusTotal integration, or production deployment configuration yet.

## Configure

Copy `.env.example` to `.env` in the project root and set your local MySQL password. `.env` is ignored by Git — never commit it.

```text
APP_ENV=development
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=mst_database
DB_USERNAME=root
DB_PASSWORD=your-local-password
FRONTEND_ORIGIN=http://localhost:8000,http://127.0.0.1:8000
```

The older names `DB_NAME` and `DB_USER` are still accepted. The PDO connection lives in `backend/config/Database.php` (exceptions on, associative fetch, native prepared statements).

## Run locally

From the project root, in two terminals:

```powershell
php -S localhost:8081 backend/public/index.php   # API  -> http://localhost:8081/api
php -S localhost:8000 router.php                 # site -> http://localhost:8000/login.html
```

Check the database connection (development only; disabled when `APP_ENV=production`):

```text
http://localhost:8081/api/health/database
```

If the API cannot be reached at all, pages fall back to their built-in demo data and show an "API unavailable" notice.

## Endpoints

| Method | URL | Module (RBAC) |
|---|---|---|
| GET | `/api/health/database` | public, development only |
| POST | `/api/auth/login` (username **or** email), `/api/auth/logout` | public |
| GET | `/api/auth/me` | signed in |
| GET | `/api/dashboard` | dashboard |
| GET | `/api/computers`, `/api/computers/{id}` | computer_monitoring |
| GET | `/api/threats` (`?severity=&status=&computerId=`), `/api/threats/{id}` | threats |
| PUT | `/api/threats/{id}/status` | threats |
| GET | `/api/scans` (`?q=&risk=&state=&source=&computerId=&from=&to=&sort=&dir=&limit=&offset=`, total in `meta`), `/api/scans/{id}` | scan_history |
| GET | `/api/scans/export` (CSV, same filters), `/api/scans/{id}/report` (text report) | scan_history |
| POST | `/api/scans/{id}/rescan`, `/api/scans/{id}/investigate`, `/api/scans/{id}/quarantine` (`{"confirm":true}`) | file_scanner (Admin only) |
| DELETE | `/api/scans/{id}/stored-file` (uploaded copy; the record is kept) | file_scanner (Admin only) |
| GET | `/api/quarantine`, `/api/quarantine/{id}` | computer_monitoring |
| POST | `/api/quarantine/{id}/release` (`reason`, `confirm: "RELEASE"`), `/api/quarantine/{id}/delete` (`confirm: "DELETE"`) | file_scanner (Admin only) |
| GET | `/api/reports` | reports |
| GET | `/api/activity` | activity_logs |
| GET, PUT | `/api/settings` (allowlisted keys only) | settings |
| GET, POST / GET, PUT, DELETE | `/api/users`, `/api/users/{id}` (Tenant accounts) | user_management |
| GET, POST / GET, PUT, DELETE | `/api/admins`, `/api/admins/{id}` (Admin and Super Admin accounts) | admin_management |
| GET / PUT | `/api/permissions`, `/api/permissions/{role}` | permissions |
| GET / POST | `/api/file-scanner` (engines and limits / multipart upload `file`, optional `submitToVirusTotal`, `force`) | file_scanner (Admin only) |
| GET | `/api/file-events` (`?computerId=&type=&status=`), `/api/file-events/{id}` (with scan history) | computer_monitoring |
| PUT | `/api/file-events/{id}` (`classification`: Normal/Confidential, `status`: Reviewed) | computer_monitoring |
| POST | `/api/file-events/{id}/scan` (asks the agent on that PC to scan the file), `/api/file-events/{id}/quarantine` | file_scanner (Admin only) |
| POST | `/api/agent/heartbeat`, `/api/agent/events`, `/api/agent/scan-jobs` (scans + quarantine actions), `/api/agent/scan-results`, `/api/agent/action-results` | lab-PC agent (device token, no user session) |

List endpoints accept `?limit=` (1–500) and `?offset=`. Responses use `{ "success": true, "message": "...", "data": ... }` or `{ "success": false, "message": "...", "error": { "code": "..." } }` with 200/201/400/401/403/404/405/409/422/500 status codes. Database errors are logged server-side and never returned to the client.

## Authentication and RBAC

Only Active Super Admin and Admin accounts can sign in. Passwords are stored with `password_hash()` and checked with `password_verify()`. The account is re-read from the database on every request, so deactivating an account or changing its role takes effect immediately.

Every endpoint checks a module. The fixed MST role policy in `backend/middleware/RoleMiddleware.php` is authoritative (Super Admin: everything except File Scanner; Admin: everything except User Management, Admin Management and Permissions). The `permissions` table is then consulted: a row with `allowed = 0` revokes that module, and a missing row falls back to the policy. The database can narrow access but can never grant a module the policy forbids, and Super Admin cannot remove its own access to Permissions.

`/api/users` manages Tenant accounts only and `/api/admins` manages Admin and Super Admin accounts. The primary Super Admin and the signed-in account cannot be deactivated or removed, and Super Admin accounts cannot be deleted. Duplicate emails or usernames return `409`.

Logins (successful and failed), logouts, account changes, permission changes, threat status changes and settings changes are written to `activity_logs` with the client IP. Only field names are logged — never passwords or other secrets, and never the text typed into the login form.

## Monitoring agent (Phases 8–9)

Lab PCs run the Python agent in `agent/` (see `agent/README.md`). Apply `database/migrations/phase9_agent.sql` once to an existing database; it adds agent columns to `computers` and the `file_events` table.

- Register a PC and get its device token (shown once; only its SHA-256 hash is stored): `php backend/tools/register-agent.php MST-PC-002 LAB-PC-02 192.168.1.21`
- For lab PCs to reach the API, start it on all interfaces: `php -S 0.0.0.0:8081 backend/public/index.php` (the website can stay on `localhost:8000`).
- Agents authenticate with `X-Device-Id` + `Authorization: Bearer <token>`. Heartbeats update the computer's status, resources and `last_heartbeat_at`; a computer whose last heartbeat is older than the **Offline Threshold** setting (minimum 45 s) is shown offline.
- `/api/agent/events` accepts up to 100 events per request. Invalid events are skipped and counted; repeated events (same `uid`) are ignored, so agent retries are safe.

## Detected files and on-PC scanning (Phase 11)

Apply `database/migrations/phase11_files.sql` once (after `phase9_agent.sql`). The **Detected Files** page lists every file the agents report with its activity (new/deleted), size, date, risk level and classification.

- **Classification:** MST suggests *Possibly confidential* when the file name or folder contains words such as payroll, salary, grades, exam, password or confidential; an admin confirms **Confidential** or **Normal**.
- **Risk before a scan** comes from the file name only (double extension such as `grades.pdf.exe` → High, programs/scripts → Low).
- **Scan:** an Admin clicks *Scan*; the agent on that PC picks the job up within a few seconds, re-hashes the file and checks it (double extension, a Windows program disguised as another file type, programs downloaded from the internet via the Windows "Mark of the Web"). The server then checks the SHA-256 against `hash_blocklist` and stores the verdict in `scans`: Critical/High → **THREAT** (a threat record is created and the computer is marked *threat*), Medium → **WARNING**, Low/Safe → **SAFE**. Files are never uploaded; the agent only scans paths inside its watch folders.
- `hash_blocklist` starts with the harmless **EICAR anti-virus test file**, so a THREAT result can be demonstrated safely. Add known-bad hashes in MySQL Workbench: `INSERT INTO hash_blocklist (sha256, name, severity, source) VALUES ('<sha256>', '<name>', 'HIGH', 'Manual');`. A VirusTotal hash lookup can be added later.

## VirusTotal (Phase 11)

Set `VIRUSTOTAL_API_KEY` in `.env` (free key from virustotal.com). After the agent scans a file, the server looks up the file's SHA-256 (never the file) and adds a finding: 10+ engines → Critical, 3+ → High, 1–2 malicious or 2+ suspicious → Medium, otherwise informational. Results are cached for 24 hours in `hash_reputation` (failed lookups are not cached and are retried next time); lookup problems never fail a scan. On Windows, PHP uses the Windows certificate store for HTTPS; if your PHP build cannot, set `VIRUSTOTAL_CA_BUNDLE` to a CA file (e.g. `cacert.pem`).

## Security (Phase 12)

Apply `database/migrations/phase12_security.sql` once (after `phase11_files.sql`). See `SECURITY.md` for the full list. API behaviour to know when calling it directly:

- Sign-in returns `csrfToken`; `/api/auth/me` returns it again (plus `sessionTimeoutSeconds`). Every POST/PUT/DELETE with a browser session must send it as `X-CSRF-Token`, otherwise `403 CSRF_INVALID`. Agent endpoints use device tokens instead.
- Too many failed sign-ins → `429 LOGIN_LOCKED` with `Retry-After`. An idle or 12-hour-old session → `401 SESSION_EXPIRED`.
- Request bodies over 1 MB → `413`. New and changed passwords follow the *Require Strong Password* setting.
- Tools: `php backend/tools/set-password.php <username>`, `php backend/tools/register-agent.php --revoke <DEVICE-ID>`.


## File scanner (Phase 13)

`ScanService` collects the evidence (antivirus engines in `helpers/Antivirus.php`, VirusTotal, the hash blocklist and `helpers/FileAnalyzer.php`), `helpers/ScanClassifier.php` turns it into the risk level (Safe / Medium / High / Unknown / Failed) and evidence strength, and `MySQLRepository::completeScan()` stores it. Uploaded files are kept in `backend/storage/uploads` (random names, outside the website) for the retention period. See [`../SCANNER.md`](../SCANNER.md).
