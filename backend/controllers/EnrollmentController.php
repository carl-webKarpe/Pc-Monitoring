<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validation.php';
require_once __DIR__ . '/../middleware/RoleMiddleware.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';
require_once __DIR__ . '/PhoneAuthController.php';

// Computers > Add Computers: enrollment keys. One key enrolls many lab PCs (each gets its own device ID and token)
// until it expires, reaches its PC limit or is revoked. The key is shown once; only its SHA-256 hash is stored.
final class EnrollmentController
{
    // No 0/O, 1/I/L: easy to read aloud and type. 16 characters from 31 = about 79 random bits.
    public const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
    private const HOURS = [1, 8, 24, 72, 168];

    public static function index(string $method, ?string $id): never
    {
        if ($id === null && $method === 'GET') self::list();
        if ($id === null && $method === 'POST') self::create();
        if ($id !== null && $method === 'DELETE') self::revoke($id);
        Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
    }

    /** Upper-case, without spaces or dashes; null when it cannot be a key. */
    public static function normalize(mixed $key): ?string
    {
        if (!is_string($key)) return null;
        $clean = strtoupper(preg_replace('/[\s-]+/', '', $key) ?? '');
        return preg_match('/^[' . self::ALPHABET . ']{16}$/', $clean) ? $clean : null;
    }

    private static function list(): never
    {
        RoleMiddleware::allowModule('computer_monitoring');
        Response::success('Request successful', ['keys' => MySQLRepository::listEnrollmentKeys(), 'serverUrl' => PhoneAuthController::publicApiUrl()]);
    }

    private static function create(): never
    {
        $user = RoleMiddleware::allowModule('computer_monitoring');
        $data = Validation::body();
        $label = trim((string)($data['label'] ?? ''));
        $hours = $data['hours'] ?? 8;
        $maxUses = $data['maxUses'] ?? 30;
        $errors = [];
        if ($label === '') $label = 'Lab PCs';
        if (!preg_match('/^.{1,80}$/u', $label) || preg_match('/[\x00-\x1F\x7F<>]/', $label)) $errors['label'] = 'Use up to 80 characters, without < or >';
        if (!in_array($hours, self::HOURS, true)) $errors['hours'] = 'Choose 1, 8, 24, 72 or 168 hours';
        if (!is_int($maxUses) || $maxUses < 1 || $maxUses > 500) $errors['maxUses'] = 'Number of PCs must be 1-500';
        if ($errors !== []) Validation::fail($errors);

        $key = '';
        for ($i = 0; $i < 16; $i++) $key .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
        $id = MySQLRepository::createEnrollmentKey(hash('sha256', $key), $label, $maxUses, $hours, (int)$user['id']);
        MySQLRepository::log((int)$user['id'], 'ENROLLMENT_KEY_CREATED', "Created enrollment key \"$label\" for up to $maxUses PC(s), valid $hours hour(s)", 'enrollment_key', (string)$id);
        $display = implode('-', str_split($key, 4));
        Response::success('Enrollment key created. Copy it now: it is shown only once.', [
            'id' => $id, 'key' => $display, 'serverUrl' => PhoneAuthController::publicApiUrl(), 'record' => MySQLRepository::findEnrollmentKey($id),
        ], 201);
    }

    private static function revoke(string $id): never
    {
        $user = RoleMiddleware::allowModule('computer_monitoring');
        $key = MySQLRepository::findEnrollmentKey(Validation::id($id));
        if (!$key) Response::error('Enrollment key not found', 'NOT_FOUND', 404);
        if (!MySQLRepository::revokeEnrollmentKey((int)$key['id'])) Response::error('This key is already revoked', 'ALREADY_REVOKED', 409);
        MySQLRepository::log((int)$user['id'], 'ENROLLMENT_KEY_REVOKED', "Revoked enrollment key \"{$key['label']}\" ({$key['uses']} PC(s) enrolled)", 'enrollment_key', (string)$key['id']);
        Response::success('Enrollment key revoked. PCs already added keep working.', MySQLRepository::findEnrollmentKey((int)$key['id']));
    }
}
