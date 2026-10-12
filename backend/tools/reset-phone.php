<?php
declare(strict_types=1);

// Removes every paired phone of an account (lost or replaced phone, or browser data cleared on the phone).
// The account then signs in with its password only until a phone is paired again in Settings.
// Run on the MST server from the project root:
//   php backend/tools/reset-phone.php superadmin

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

$login = $argv[1] ?? '';
if ($login === '') { fwrite(STDERR, "Usage: php backend/tools/reset-phone.php <username-or-email>\n"); exit(2); }
try {
    $account = MySQLRepository::findForLogin($login);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Could not reach the database: ' . $exception->getMessage() . "\n"); exit(1);
}
if (!$account) { fwrite(STDERR, "No account found for \"$login\".\n"); exit(2); }

$removed = MySQLRepository::revokeAllDevices((int)$account['id']);
MySQLRepository::log(null, 'PHONE_RESET', "All paired phones of {$account['username']} were removed from the server console ($removed)", 'user', (string)$account['id']);
echo $removed ? "Removed $removed paired phone(s) of {$account['username']}. Sign in with the password, then pair a phone again in Settings > Phone Verification.\n" : "{$account['username']} had no paired phone.\n";
