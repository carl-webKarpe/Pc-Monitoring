# Monitoring System Threat

Monitoring System Threat (MST) is a frontend-only cybersecurity monitoring platform prototype for a capstone project. It provides a public landing page, role-aware login flow, SOC dashboard, authorized computer monitoring views, threat oversight, and file scanning workflows.

## Accounts and Roles

`database/seed.sql` creates two accounts, **superadmin** (Super Admin) and **admin** (Admin). Set your own strong passwords right after installing, on the MST server:

```powershell
php backend/tools/set-password.php superadmin
php backend/tools/set-password.php admin
```

Passwords are never stored or documented in plain text; only `password_hash()` values are kept in MySQL. (If you installed an earlier version of MST, the old demo passwords keep working until you change them.)

### Super Admin

- Monitor authorized PCs and view network activity
- View computer information, threats, detected files, scan history and scan results
- Manage and add administrators and users, and role permissions
- View reports and activity logs
- Manage system settings

Does not have access to the `File Scanner` (and therefore cannot start file scans).

### Admin

- Monitor authorized PCs and view network activity
- View computer information, threats and detected files
- Scan files and view scan history
- View reports and activity logs
- Access system settings

Does not have access to `Admin Management`, `User Management` or `Permissions`.

## Frontend Role Notes

The role is stored in `sessionStorage` for this prototype. The shared `renderSidebar(role)` function renders the correct navigation for each role. Restricted pages show an access message when opened manually by the wrong role. These checks are only presentation-layer behavior; real authorization must be enforced by the future PHP backend.

## Project Structure

```text
Monitoring-System-Threat/
├── index.html
├── login.html
├── dashboard.html
├── monitoring.html
├── computers.html
├── threats.html
├── file-scanner.html
├── scan-history.html
├── admins.html
├── users.html
├── reports.html
├── activity-logs.html
├── settings.html
├── management/
│   ├── users.html
│   ├── admins.html
│   └── permissions.html
├── assets/
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── app.js
│       ├── computers.js
│       ├── dashboard.js
│       ├── management.js
│       ├── monitoring.js
│       ├── settings.js
│       └── scanner.js
└── README.md
```

## Current Development Phase

Phase 1: Landing Page + Login + Initial UI

Phase 2: Main SOC Dashboard

Current: Frontend role separation and navigation

Future:

- PHP REST API
- MySQL database
- Python monitoring agent
- LAN/Ethernet communication
- File monitoring
- SHA-256 hashing
- VirusTotal API integration
- Real authentication
- Server-side RBAC

## Running the Prototype

Open `index.html` in a browser, or serve the folder with any static HTTP server. No backend, database, API, or real network monitoring is connected yet. All displayed monitoring values are demo data for authorized-environment workflow demonstrations.

## Phase 3 - Computer Monitoring

Computer Monitoring provides administrators with a centralized interface for viewing authorized computers, their connection status, system information, agent status, network information, and security status.

Current implementation: frontend demo data.

Future implementation:

- Python Agent
- LAN/Ethernet communication
- PHP REST API
- Database persistence
- Real-time monitoring

## Phase 5 - Threat Management & Scan History

Phase 5 introduces centralized threat management, security events, and scan history management.

Features:

- Threat Management
- Threat Details
- Threat Filtering
- Threat Status Management
- Scan History
- Scan Details
- Security Events
- Threat Statistics
- Scan Statistics

Current implementation: frontend demo data.

Future implementation:

- PHP REST API
- MySQL persistence
- Python Agent security event collection
- VirusTotal API integration

## Phase 6 - PHP Backend REST API Foundation

Phase 6 adds a PHP REST API foundation with JSON responses, PHP sessions, hashed demo authentication, server-side RBAC, validation helpers, and an in-memory mock repository.

API documentation and the local run command are in [backend/README.md](backend/README.md).

Current limitations:

- No MySQL or persistent backend data yet
- No Python Agent or LAN monitoring
- No real malware/file scanning engine
- No VirusTotal integration
- Accounts must be given your own passwords (`backend/tools/set-password.php`)

MySQL integration is planned for Phase 7.

## Phase 7 - MySQL Database Integration

Phase 7 replaces the temporary mock data layer with a PDO-backed MySQL repository. The database name defaults to `mst_database` and can be configured with `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD` in a local `.env` file copied from `.env.example`.

### Database setup

1. Copy `.env.example` to `.env` and set local MySQL credentials. Do not commit `.env`.
2. Create the schema and seed hashed demo accounts:

```powershell
mysql -u root -p < database/schema.sql
mysql -u root -p mst_database < database/seed.sql
```

For a complete reset and reseed from the project root, run `mysql -u root -p < database/reset.sql` in the MySQL command-line client. `SOURCE` commands in the reset script are MySQL-client commands; do not paste that file into phpMyAdmin. This deletes all local MST data, so use it only during development. For phpMyAdmin, import `schema.sql` first and then `seed.sql` separately.

To run the project, start the API with `php -S localhost:8081 backend/public/index.php` and serve the site with `php -S localhost:8000 router.php` from the project root (the router serves only the website's files and blocks `.env`, `backend/`, `database/` and `agent/`), then open `http://localhost:8000/login.html`. Check the database connection at `http://localhost:8081/api/health/database`. Full API details are in [backend/README.md](backend/README.md).

The dashboard, Computer Monitoring, Threats, Scan History, Reports, Activity Logs, Settings, User/Admin Management and Permissions pages now read MySQL data through the API. If the API cannot be reached, those pages fall back to their built-in demo data and show an "API unavailable" notice.

The seed stores bcrypt password hashes generated with `password_hash()`, never plaintext passwords. Computer, CPU/memory, agent, threat, and scan values remain demonstration data; the Python Agent, LAN monitoring, VirusTotal, and real file scanning are future work.

## Phase 4 - Super Admin Management

Phase 4 introduces the Super Admin Management module.

Features:

- User Management
- Admin Management
- Permission Management
- System Settings
- Security Settings
- Monitoring Settings
- Notification Settings
- Interface Settings

Current implementation: frontend demo/prototype.

Future implementation:

- PHP REST API
- MySQL database
- Server-side authentication
- Server-side RBAC
- Secure password hashing
- Audit logging
- Persistent system settings

Set your own account passwords with `backend/tools/set-password.php` before using MST.

## Phases 8–9 - Monitoring Agent and Agent API

Each authorized lab PC runs the Python agent in [`agent/`](agent/README.md). It sends a heartbeat (online status, IP, CPU, memory, disk) and reports new and deleted files in the folders you configure (name, location, size, time, SHA-256) to the PHP API, which stores them in MySQL (`computers`, `file_events`). The dashboard shows real online/offline status, recent file activity per computer, and new-file notifications on the bell icon. The agent only collects file metadata and hashes; it does not upload files, log keystrokes, capture the screen or run hidden.

Existing databases: run `database/migrations/phase9_agent.sql` once. Register each PC with `php backend/tools/register-agent.php <DEVICE-ID> <HOSTNAME> [IP]`. Scanning detected files is Phase 11.

## Phase 11 - Detected Files and On-PC Scanning

The **Detected Files** page (Threat Management) shows every file the agents report, with activity, size, date, risk level and classification (MST suggests *Possibly confidential*; the admin confirms Confidential or Normal). An Admin can request a scan; the agent on that PC checks the file locally, the server adds a hash-blocklist check, and the result is stored in `scans` (THREAT results also create a threat). Super Admin can view and classify files but, as with the File Scanner, cannot scan. Existing databases: run `database/migrations/phase11_files.sql` once after `phase9_agent.sql`.

## Phase 11 - VirusTotal

When a file is scanned, the server also looks up its **SHA-256** on VirusTotal (only the hash is sent, never the file) and shows how many security vendors flag it, with a link to the report. Results are cached for 24 hours. Add a free API key as `VIRUSTOTAL_API_KEY` in `.env`; without a key, scans work as before and show "VirusTotal not configured".

## Phase 12 - Security Hardening

Login lockout, idle session timeout, CSRF protection, strong passwords, security headers, web-folder protection, device-token revocation and security logging. See [SECURITY.md](SECURITY.md) for every measure, how to test it, and how to enable HTTPS. Existing databases: run `database/migrations/phase12_security.sql` once after `phase11_files.sql`.


## Phase 13 - Real File Scanner

Real scanning with antivirus engines (Microsoft Defender, built into Windows, and/or ClamAV) on the lab PCs and on the MST server, VirusTotal, the hash blocklist and static file analysis. Five honest risk levels (**Safe, Medium, High, Unknown, Failed**) with an evidence-strength rating instead of invented percentages; a full Scan History table (search, filters, sorting, paging, CSV and report export); real uploads on the File Scanner page; automatic scans of new files; quarantine / release / delete on lab PCs; investigations; a dashboard built only from database data. Setup, rules and testing: **[SCANNER.md](SCANNER.md)**. Existing databases: run `database/migrations/phase13_scanner.sql` once after `phase12_security.sql`.
