# MST Security (Phase 12)

Monitoring System Threat runs inside an authorized computer laboratory. This page lists every security control, where it is implemented, and how to demonstrate it.

## Scope and ethics

- The agent runs **only on authorized lab computers**, as a visible program that logs everything it does.
- It watches **only the configured folders** and collects **file metadata and SHA-256 hashes**. It never uploads file contents, records keystrokes, captures the screen, controls the computer or hides itself.
- On-PC scans only read files inside the agent's watch folders (paths outside them are refused). VirusTotal receives **only the SHA-256 hash**.

## Controls

| Area | Control | Where |
|---|---|---|
| Authentication | Passwords stored with `password_hash()` / checked with `password_verify()`; plaintext passwords are never stored, logged or returned | `AuthController`, `MySQLRepository` |
| | Only active Super Admin and Admin accounts can sign in; the account is re-checked on every request (deactivation or role changes apply immediately) | `AuthMiddleware::requireAuth` |
| | **Login lockout**: after *N* wrong passwords for an account (setting *Login Attempt Limit*, default 5) or 3×N failures from one IP address, sign-in is refused for 15 minutes (HTTP 429 + `Retry-After`) | `AuthController::login` |
| | Same response and same password-hashing time for unknown usernames, so attackers cannot discover account names | `Security::verifyAgainstDummy` |
| | **Strong passwords** (setting *Require Strong Password*): 8+ characters with upper- and lowercase letters, a number and a symbol, not containing the username | `Security::passwordProblem` |
| | Change any password from the server console: `php backend/tools/set-password.php <username>` | `backend/tools/set-password.php` |
| Sessions | Cookie is `HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS; session ID regenerated at sign-in; strict session mode | `config.php`, `AuthMiddleware` |
| | **Idle timeout** from the *Session Timeout* setting (5 min – 24 h, default 30 min) and a 12-hour maximum; the user is sent to the login page with "Your session expired" | `AuthMiddleware`, `assets/js/api.js` |
| API authorization | Every endpoint checks a module of the fixed MST role policy, then the `permissions` table (which can only narrow it). Admin cannot use User/Admin Management or Permissions; Super Admin cannot use the File Scanner | `RoleMiddleware` |
| | **CSRF protection**: every POST/PUT/DELETE from a browser session must send the session's secret `X-CSRF-Token`; other websites cannot read or forge it | `Security::requireCsrf`, `assets/js/api.js` |
| | CORS only for the configured website origin(s), with credentials | `cors.php`, `FRONTEND_ORIGIN` |
| Device authentication | Each lab PC has its own random 256-bit token; only its SHA-256 hash is stored; agent requests must send `X-Device-Id` + `Authorization: Bearer` | `AgentAuth`, `register-agent.php` |
| | Revoke a lost or replaced PC instantly: `php backend/tools/register-agent.php --revoke MST-PC-002` | `register-agent.php` |
| Input validation | Allow-lists for roles, statuses, severities, scan types, settings keys and filters; type and length checks (by character); IDs must be positive integers; request bodies limited to 1 MB; agent events limited to 100 per request | `Validation`, `AgentController` |
| | All SQL uses PDO prepared statements with native (non-emulated) prepares; table/column names come only from fixed lists | `MySQLRepository` |
| | Values from the database/agents are HTML-escaped before display (stored-XSS protection) | `mstEscape` in `assets/js/app.js` |
| Secure file handling | Uploads (File Scanner, Admin only): 32 MB limit, stored under a random name with no extension in `backend/storage` (outside the website, blocked by `router.php`/`.htaccess`), never opened or run, deleted after the retention period. Lab-PC files are never uploaded. The agent hashes files locally and only scans inside its watch folders (`..` tricks and other folders are refused) | `agent/mst_agent/scanner.py` |
| | **Web-folder protection**: the website router serves only HTML/CSS/JS/images/fonts from allowed folders; `.env`, `.git`, `backend/`, `database/`, `agent/` (device token) and `.venv/` return 404. `.htaccess` applies the same rules on Apache/XAMPP | `router.php`, `.htaccess` |
| Errors | Database errors and stack traces are logged on the server only; users get a generic message; `display_errors` is off | `backend/public/index.php` |
| Headers | API: `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, HSTS over HTTPS. Website: `frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'`, `X-Frame-Options: DENY`, `nosniff` | `index.php`, `router.php` |
| Quarantine | Only Admin, only after confirmation; the agent verifies the SHA-256 before moving, restoring or deleting a file; High-risk files cannot be released; every release needs a written reason; files on lab PCs are only deleted after being quarantined | `QuarantineController`, `agent/mst_agent/quarantine.py` |
| Logging | Activity Logs record scan requests, uploads, investigations, report exports, quarantine/release/delete requests and results, sign-in, failed sign-in, lockout, sign-out, session expiry, denied access (`ACCESS_DENIED`), account/permission/settings changes, threat status changes, file classification, scan requests, agent registration/revocation and console password resets — with user and IP address. Passwords, tokens and typed login names are never logged | `MySQLRepository::log` |
| Secrets | `.env` (database password, VirusTotal key) and `agent/config.json` (device token) are ignored by Git and blocked by the web router | `.gitignore`, `router.php` |

## Run commands (secure defaults)

```powershell
php -S 0.0.0.0:8081 backend/public/index.php   # API (lab PCs connect here)
php -S localhost:8000 router.php                 # website, only on this computer
```

## HTTPS (recommended when the dashboard is used over the network)

PHP's built-in server only speaks HTTP. For HTTPS on the lab network, put Apache (XAMPP) in front of the API:

1. Create a certificate for the MST server (for example with the `makecert` tool in XAMPP's `apache` folder, or `openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout mst.key -out mst.crt -subj "/CN=192.168.1.10"`).
2. In `xampp\apache\conf\extra\httpd-ssl.conf`, enable a `VirtualHost *:8443` with `SSLEngine on`, `SSLCertificateFile mst.crt`, `SSLCertificateKeyFile mst.key`, and forward requests to the API:
   ```apache
   ProxyPass        /api http://127.0.0.1:8081/api
   ProxyPassReverse /api http://127.0.0.1:8081/api
   RequestHeader set X-Forwarded-Proto "https"
   ```
   (enable `mod_ssl`, `mod_proxy`, `mod_proxy_http` and `mod_headers`). Keep the PHP API itself on `127.0.0.1:8081` so it is only reachable through Apache.
3. Lab PCs: set `"server_url": "https://192.168.1.10:8443/api"` and `"tls_ca_bundle": "mst.crt"` (copy the certificate next to `config.json`). The agent always verifies the certificate; there is no option to switch verification off.
4. The API then marks the session cookie `Secure` and sends `Strict-Transport-Security`.

## Demonstrating the controls

| Control | How to show it |
|---|---|
| Lockout | Set *Login Attempt Limit* to 3, enter a wrong password 3 times, then the right one → "Too many failed login attempts" |
| Idle timeout | Set *Session Timeout* to 5 minutes, leave a non-refreshing page (e.g. Settings) for 5 minutes, click anything → login page with "Your session expired" |
| Role enforcement | As Admin open `http://localhost:8081/api/users` → 403, and an `ACCESS_DENIED` entry in Activity Logs |
| CSRF | In the browser console run `fetch('http://localhost:8081/api/settings',{method:'PUT',credentials:'include',body:'{}'})` → 403 "Security token missing or invalid" |
| Web-folder protection | Open `http://localhost:8000/.env` or `/agent/config.json` → 404 |
| Device revoke | `php backend/tools/register-agent.php --revoke MST-PC-002` → that PC shows offline and its agent reports "Device not authorized" |

## Known limitations / future work

- Two-factor authentication is not implemented (the setting is shown but has no effect).
- The website loads Tailwind CSS and Font Awesome from CDNs; a strict `script-src` Content-Security-Policy needs those bundled locally (Phase 13).
- HTTPS requires the Apache setup above; the built-in PHP server is for the lab/demo environment.
