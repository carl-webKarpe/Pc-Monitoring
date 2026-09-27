# MST PHP API Foundation

Phase 7 uses a PHP REST API with PHP sessions, PDO, MySQL persistence, and server-side RBAC. Computer telemetry and security scan records remain demonstration data. It does not include a Python Agent, LAN monitoring, a real scanner, VirusTotal, or production deployment configuration.

## Run locally

From the project root:

```powershell
php -S localhost:8081 backend/public/index.php
```

The API base URL is `http://localhost:8081/api`. The frontend API helper uses this URL by default and sends session cookies.

## Endpoints

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET|POST /api/users`, `GET|PUT|DELETE /api/users/{id}`
- `GET|POST /api/admins`, `GET|PUT|DELETE /api/admins/{id}`
- `GET /api/computers`, `GET /api/computers/{id}`
- `GET /api/threats`, `GET /api/threats/{id}`, `PUT /api/threats/{id}/status`
- `GET /api/scans`, `GET /api/scans/{id}`
- `GET /api/reports`
- `GET /api/activity`
- `GET /api/permissions`, `PUT /api/permissions/{role}`
- `GET|PUT /api/settings`
- `POST /api/file-scanner` returns a Phase 6 not-implemented response for Admins and rejects Super Admins.

## Authentication and RBAC

Demo accounts are local-development credentials only. Password verification uses `password_hash()` and `password_verify()`, sessions regenerate after login, and passwords/hashes are excluded from API responses. Super Admin is required for users, admins, and permission changes. Both roles can read computers, threats, scans, reports, activity, and settings. Only Admin may reach the future scanner API boundary.

The database schema is in `database/schema.sql` and seed data is in `database/seed.sql`. The MySQL repository can later be extended for agent telemetry without changing the API contract.
