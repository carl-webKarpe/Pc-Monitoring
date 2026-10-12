<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validation.php';
require_once __DIR__ . '/../helpers/Security.php';
require_once __DIR__ . '/../middleware/AuthMiddleware.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

/**
 * Super Admin sign-in approved on a paired phone (Phase 14).
 *
 * Pairing (once, while signed in): Settings shows a QR code; the phone opens it and receives a secret key in a
 * cookie. Only the key's SHA-256 is stored (trusted_devices).
 * Sign-in: after the correct password the laptop shows a QR code; the paired phone scans it, compares the
 * 2-digit number and taps Approve; the laptop (polling /auth/approval) is then signed in. QR codes are random,
 * one-time and expire after 2 minutes (pairing: 5 minutes).
 */
final class PhoneAuthController
{
    private const LOGIN_TTL = 120;
    private const PAIR_TTL = 300;
    private const COOKIE = 'mst_phone';
    private const COOKIE_DAYS = 400;

    public static function enabled(): bool { return mst_config()['superadmin_phone_login']; }

    /** Pairing is required for Super Admin accounts only (MST role rules). */
    public static function appliesTo(array $account): bool { return self::enabled() && $account['role'] === 'Super Admin'; }

    // ---- sign-in (laptop) ------------------------------------------------------------------------------

    /** Called by AuthController::login after a correct Super Admin password when a phone is paired. */
    public static function startLoginApproval(array $account): never
    {
        [$token, $hash] = self::newToken();
        $match = random_int(10, 99);
        $requestId = MySQLRepository::createPhoneRequest('login', $hash, (int)$account['id'], $match, Security::clientIp(), self::agent(), self::LOGIN_TTL);
        mst_start_session();
        session_regenerate_id(true);
        // Not signed in yet: the session only remembers which approval this browser is waiting for.
        $_SESSION = ['mst_pending_login' => ['requestId' => $requestId, 'userId' => (int)$account['id']]];
        MySQLRepository::log((int)$account['id'], 'LOGIN_APPROVAL_REQUESTED', 'Password correct; waiting for approval on the paired phone', 'user', (string)$account['id']);
        Response::success('Scan the QR code with your paired phone to finish signing in', [
            'approvalRequired' => true, 'qrUrl' => self::phoneUrl($token), 'matchNumber' => $match, 'expiresInSeconds' => self::LOGIN_TTL,
        ]);
    }

    /** The sign-in page polls this every 2 seconds while the QR code is shown. */
    public static function approvalStatus(): never
    {
        mst_start_session();
        $pending = $_SESSION['mst_pending_login'] ?? null;
        if (!is_array($pending)) Response::error('No sign-in is waiting for approval. Sign in again.', 'NO_PENDING_LOGIN', 401);
        $request = MySQLRepository::findPhoneRequest((int)$pending['requestId']);
        $status = $request['status'] ?? 'expired';
        if ($status === 'pending') Response::success('Waiting for approval', ['status' => 'pending', 'secondsLeft' => (int)$request['secondsLeft']]);
        unset($_SESSION['mst_pending_login']);
        if ($status === 'approved' && MySQLRepository::updatePhoneRequest((int)$request['id'], 'approved', 'used')) {
            $account = MySQLRepository::findAccount((int)$pending['userId']);
            if (!$account || $account['status'] !== 'Active' || !in_array($account['role'], AuthMiddleware::LOGIN_ROLES, true)) Response::error('This account cannot sign in', 'INVALID_CREDENTIALS', 401);
            $user = Security::publicUser($account);
            AuthMiddleware::startUserSession($user);
            MySQLRepository::touchLogin((int)$account['id']);
            MySQLRepository::log((int)$account['id'], 'LOGIN', 'Successful login (approved on paired phone "' . $request['deviceName'] . '")', 'user', (string)$account['id']);
            Response::success('Login successful', ['status' => 'approved', 'user' => $user, 'csrfToken' => Security::csrfToken()]);
        }
        if ($status === 'denied') Response::error('Sign-in was denied on your phone.', 'LOGIN_DENIED', 401);
        Response::error('The QR code expired. Sign in again to get a new one.', 'APPROVAL_EXPIRED', 401);
    }

    // ---- pairing (Settings, signed-in Super Admin) ------------------------------------------------------

    public static function devices(string $method, ?string $id): never
    {
        $user = AuthMiddleware::requireAuth();
        if ($user['role'] !== 'Super Admin') {
            MySQLRepository::log((int)$user['id'], 'ACCESS_DENIED', "{$user['role']} tried to manage phone verification", 'module', 'phone_verification');
            Response::error('Forbidden', 'FORBIDDEN', 403);
        }
        $userId = (int)$user['id'];
        if ($method === 'GET' && $id === null) {
            $pairing = isset($_SESSION['mst_pairing_request']) ? MySQLRepository::findPhoneRequest((int)$_SESSION['mst_pairing_request']) : null;
            Response::success('Paired phones', ['enabled' => self::enabled(), 'devices' => MySQLRepository::listDevices($userId), 'pairing' => $pairing ? ['status' => $pairing['status'], 'secondsLeft' => (int)$pairing['secondsLeft'], 'deviceName' => $pairing['deviceName']] : null]);
        }
        if ($method === 'POST' && $id === null) {
            [$token, $hash] = self::newToken();
            $_SESSION['mst_pairing_request'] = MySQLRepository::createPhoneRequest('pair', $hash, $userId, null, Security::clientIp(), self::agent(), self::PAIR_TTL);
            MySQLRepository::log($userId, 'PHONE_PAIRING_STARTED', 'Pairing QR code shown in Settings', 'user', (string)$userId);
            Response::success('Scan the QR code with your phone', ['qrUrl' => self::phoneUrl($token), 'expiresInSeconds' => self::PAIR_TTL], 201);
        }
        if ($method === 'DELETE' && $id !== null) {
            if (!MySQLRepository::revokeDevice(Validation::id($id), $userId)) Response::error('Phone not found', 'NOT_FOUND', 404);
            MySQLRepository::log($userId, 'PHONE_REMOVED', "Removed paired phone #$id" . (MySQLRepository::activeDeviceCount($userId) === 0 ? ' (no phone left: sign-in uses the password only)' : ''), 'user', (string)$userId);
            Response::success('Phone removed', ['devices' => MySQLRepository::listDevices($userId)]);
        }
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    // ---- pages opened on the phone ----------------------------------------------------------------------

    public static function page(): never
    {
        $token = is_string($_GET['t'] ?? null) ? $_GET['t'] : '';
        $request = self::requestForToken($token);
        if (!$request || $request['status'] !== 'pending') self::html('QR code expired', '<p>This QR code has expired or was already used.</p><p class="muted">Go back to the laptop and start again.</p>', 'expired');
        $esc = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
        if ($request['purpose'] === 'pair') {
            $name = self::guessDeviceName();
            self::html('Pair this phone', '<p>Use this phone to approve sign-ins of the MST account <b>' . $esc($request['username']) . '</b>?</p>
                <form method="post"><input type="hidden" name="t" value="' . $esc($token) . '"><input type="hidden" name="decision" value="pair">
                <label>Name for this phone<input name="name" maxlength="60" value="' . $esc($name) . '"></label>
                <button class="approve" type="submit">Pair this phone</button></form>
                <p class="muted">The phone keeps a secret key in this browser. Do not clear this browser\'s data, or pair again.</p>');
        }
        $device = self::deviceFromCookie();
        if (!$device || (int)$device['userId'] !== (int)$request['userId']) {
            self::html('Phone not paired', '<p>This phone is not paired with the MST account <b>' . $esc($request['username']) . '</b>.</p><p class="muted">Pair it first: sign in on the laptop, then Settings → Phone Verification → Pair a phone. Use the same browser on this phone.</p>', 'denied');
        }
        self::html('Approve sign-in?', '<div class="match">' . $esc(str_pad((string)$request['matchNumber'], 2, '0', STR_PAD_LEFT)) . '</div>
            <p class="muted center">The laptop must show the same number.</p>
            <dl><dt>Account</dt><dd>' . $esc($request['username']) . ' (' . $esc($request['userRole']) . ')</dd>
            <dt>From</dt><dd>' . $esc($request['requesterIp'] ?? 'unknown') . ' · ' . $esc(self::browserName((string)$request['requesterAgent'])) . '</dd>
            <dt>Requested</dt><dd>' . $esc(date('M j, Y g:i:s A', strtotime((string)$request['createdAt']))) . ' (' . (int)$request['secondsLeft'] . ' s left)</dd></dl>
            <form method="post"><input type="hidden" name="t" value="' . $esc($token) . '">
            <button class="approve" name="decision" value="approve" type="submit">Approve</button>
            <button class="deny" name="decision" value="deny" type="submit">Deny</button></form>
            <p class="muted">Only approve if you are signing in yourself right now.</p>');
    }

    public static function decide(): never
    {
        $token = is_string($_POST['t'] ?? null) ? $_POST['t'] : '';
        $decision = $_POST['decision'] ?? '';
        $request = self::requestForToken($token);
        if (!$request || $request['status'] !== 'pending') self::html('QR code expired', '<p>This QR code has expired or was already used.</p><p class="muted">Go back to the laptop and start again.</p>', 'expired');
        $userId = (int)$request['userId'];

        if ($request['purpose'] === 'pair' && $decision === 'pair') {
            $name = trim(preg_replace('/[\x00-\x1F\x7F<>]/u', ' ', (string)($_POST['name'] ?? '')) ?? '');
            $name = preg_match('/^.{1,60}$/us', $name) ? $name : 'Phone';
            $secret = bin2hex(random_bytes(32));
            $deviceId = MySQLRepository::createDevice($userId, $name, hash('sha256', $secret));
            if (!MySQLRepository::updatePhoneRequest((int)$request['id'], 'pending', 'approved', $deviceId)) { MySQLRepository::revokeDevice($deviceId, $userId); self::html('QR code expired', '<p>This QR code expired. Start pairing again on the laptop.</p>', 'expired'); }
            // HttpOnly (scripts cannot read it); Lax so it is sent when the camera app opens a sign-in QR code.
            setcookie(self::COOKIE, $secret, ['expires' => time() + self::COOKIE_DAYS * 86400, 'path' => '/api/auth/phone', 'httponly' => true, 'samesite' => 'Lax', 'secure' => mst_is_https()]);
            MySQLRepository::log($userId, 'PHONE_PAIRED', "Paired phone \"$name\" for sign-in approval", 'user', (string)$userId);
            self::html('Phone paired', '<p>This phone can now approve sign-ins of <b>' . htmlspecialchars($request['username'], ENT_QUOTES, 'UTF-8') . '</b>.</p><p class="muted">You can close this page.</p>', 'approved');
        }

        if ($request['purpose'] === 'login' && in_array($decision, ['approve', 'deny'], true)) {
            $device = self::deviceFromCookie();
            if (!$device || (int)$device['userId'] !== $userId) self::html('Phone not paired', '<p>This phone is not paired with this account.</p>', 'denied');
            if ($decision === 'approve' && MySQLRepository::updatePhoneRequest((int)$request['id'], 'pending', 'approved', (int)$device['id'])) {
                MySQLRepository::touchDevice((int)$device['id']);
                MySQLRepository::log($userId, 'LOGIN_APPROVED_ON_PHONE', "Sign-in from {$request['requesterIp']} approved on \"{$device['name']}\"", 'user', (string)$userId);
                self::html('Sign-in approved', '<p>The laptop is now signing in.</p><p class="muted">You can close this page.</p>', 'approved');
            }
            if ($decision === 'deny' && MySQLRepository::updatePhoneRequest((int)$request['id'], 'pending', 'denied', (int)$device['id'])) {
                // Counts as a failed sign-in (lockout): someone who knows the password was stopped here.
                MySQLRepository::log($userId, 'LOGIN_FAILED', "Failed login attempt (denied on paired phone \"{$device['name']}\", from {$request['requesterIp']})", 'user', (string)$userId);
                self::html('Sign-in denied', '<p>The sign-in was blocked.</p><p class="muted">If you did not try to sign in, someone knows your password: change it now (php backend/tools/set-password.php).</p>', 'denied');
            }
        }
        self::html('QR code expired', '<p>This QR code has expired or was already used.</p>', 'expired');
    }

    // ---- helpers ----------------------------------------------------------------------------------------

    /** @return array{0: string, 1: string} [token for the QR code, SHA-256 stored in the database] */
    private static function newToken(): array { $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); return [$token, hash('sha256', $token)]; }

    private static function requestForToken(string $token): ?array { return preg_match('/^[A-Za-z0-9_-]{43}$/', $token) ? MySQLRepository::findPhoneRequestByToken(hash('sha256', $token)) : null; }

    private static function deviceFromCookie(): ?array
    {
        $secret = $_COOKIE[self::COOKIE] ?? '';
        return is_string($secret) && preg_match('/^[0-9a-f]{64}$/', $secret) ? MySQLRepository::findDeviceByKey(hash('sha256', $secret)) : null;
    }

    private static function agent(): ?string { $agent = (string)($_SERVER['HTTP_USER_AGENT'] ?? ''); return $agent === '' ? null : substr(preg_replace('/[\x00-\x1F\x7F]/', '', $agent) ?? '', 0, 160); }

    private static function browserName(string $agent): string
    {
        $browser = match (true) { str_contains($agent, 'Edg/') => 'Edge', str_contains($agent, 'OPR/') => 'Opera', str_contains($agent, 'Firefox/') => 'Firefox', str_contains($agent, 'Chrome/') => 'Chrome', str_contains($agent, 'Safari/') => 'Safari', default => 'Browser' };
        $system = match (true) { str_contains($agent, 'Windows') => 'Windows', str_contains($agent, 'Android') => 'Android', str_contains($agent, 'iPhone') || str_contains($agent, 'iPad') => 'iOS', str_contains($agent, 'Mac OS') => 'macOS', str_contains($agent, 'Linux') => 'Linux', default => '' };
        return trim("$browser on $system");
    }

    private static function guessDeviceName(): string
    {
        $agent = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
        if (preg_match('/Android [\d.]+; ([^;)]+)/', $agent, $match) && !in_array(trim($match[1]), ['K', 'wv'], true)) return substr(trim($match[1]), 0, 60);
        return self::browserName($agent) === 'Browser' ? 'Phone' : 'Phone (' . self::browserName($agent) . ')';
    }

    // The QR code must hold an address the phone can open: the laptop's LAN address, never "localhost".
    private static function phoneUrl(string $token): string { return self::publicApiUrl() . '/auth/phone?t=' . $token; }

    public static function publicApiUrl(): string
    {
        $configured = mst_config()['public_api_url'];
        if ($configured !== '') return $configured;
        $https = mst_is_https();
        $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
        $port = (int)($_SERVER['SERVER_PORT'] ?? 8081);
        $name = strtolower(preg_replace('/:\d+$/', '', $host) ?? $host);
        if (in_array($name, ['localhost', '127.0.0.1', '[::1]'], true)) {
            $lan = self::lanAddress();
            if ($lan !== null) $host = $lan . ':' . $port;
        }
        return ($https ? 'https' : 'http') . '://' . $host . '/api';
    }

    // Asks the operating system which local address it would use to reach the network (no packet is sent).
    private static function lanAddress(): ?string
    {
        $socket = @stream_socket_client('udp://8.8.8.8:53', $errno, $error, 1);
        if (!$socket) return null;
        $name = stream_socket_get_name($socket, false) ?: '';
        fclose($socket);
        $ip = preg_replace('/:\d+$/', '', $name) ?? '';
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !str_starts_with($ip, '127.') ? $ip : null;
    }

    // Small self-contained page for the phone (no scripts; the only styles are inline).
    private static function html(string $title, string $body, string $tone = 'info'): never
    {
        http_response_code(200);
        header('Content-Type: text/html; charset=utf-8');
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        $accent = ['approved' => '#22C55E', 'denied' => '#EF4444', 'expired' => '#FACC15'][$tone] ?? '#00D9FF';
        echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">'
            . '<title>MST · ' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</title><style>'
            . '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;background:#050B14;color:#F8FAFC;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}'
            . 'main{width:100%;max-width:420px;padding:28px 22px;border:1px solid rgba(0,217,255,.25);border-radius:18px;background:#0B1628}'
            . '.brand{color:#00D9FF;font-size:12px;letter-spacing:.2em;font-weight:700}h1{margin:6px 0 14px;font-size:24px;color:' . $accent . '}'
            . '.muted{color:#94A3B8;font-size:14px}.center{text-align:center}.match{margin:6px auto 0;width:96px;padding:10px 0;border-radius:14px;background:rgba(0,217,255,.12);color:#00D9FF;font-size:42px;font-weight:800;text-align:center;letter-spacing:.08em}'
            . 'dl{display:grid;grid-template-columns:auto 1fr;gap:6px 12px;margin:16px 0;font-size:14px}dt{color:#94A3B8}dd{margin:0;overflow-wrap:anywhere}'
            . 'label{display:grid;gap:6px;margin:14px 0;color:#94A3B8;font-size:14px}input{padding:12px;border:1px solid rgba(148,163,184,.3);border-radius:10px;background:#08111F;color:#F8FAFC;font-size:16px}'
            . 'button{display:block;width:100%;margin-top:10px;padding:14px;border:0;border-radius:12px;font-size:17px;font-weight:700;cursor:pointer}.approve{background:#00D9FF;color:#04121F}.deny{background:rgba(239,68,68,.15);color:#FECACA;border:1px solid rgba(239,68,68,.4)}'
            . '</style></head><body><main><div class="brand">MST · MONITORING SYSTEM THREAT</div><h1>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h1>' . $body . '</main></body></html>';
        exit;
    }
}
