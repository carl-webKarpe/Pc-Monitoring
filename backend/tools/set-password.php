<?php
declare(strict_types=1);

// Sets a new password for an MST account (use it to replace the demo passwords after installing).
// Run on the MST server from the project root:
//   php backend/tools/set-password.php superadmin
// The password is typed at the prompt (twice) and stored only as a password_hash().

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../helpers/Security.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

$login = $argv[1] ?? '';
if ($login === '') { fwrite(STDERR, "Usage: php backend/tools/set-password.php <username-or-email>\n"); exit(2); }

try {
    $account = MySQLRepository::findForLogin($login);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Could not reach the database: ' . $exception->getMessage() . "\n"); exit(1);
}
if (!$account) { fwrite(STDERR, "No account found for \"$login\".\n"); exit(2); }

$read = static function (string $prompt): string {
    echo $prompt;
    if (PHP_OS_FAMILY !== 'Windows') shell_exec('stty -echo 2>/dev/null');
    $value = rtrim((string)fgets(STDIN), "\r\n");
    if (PHP_OS_FAMILY !== 'Windows') { shell_exec('stty echo 2>/dev/null'); echo "\n"; }
    return $value;
};
if (PHP_OS_FAMILY === 'Windows') echo "Note: the password is visible while you type. Clear the terminal afterwards (cls).\n";
$password = $read("New password for {$account['username']} ({$account['role']}): ");
if ($password !== $read('Type it again: ')) { fwrite(STDERR, "The passwords do not match. Nothing was changed.\n"); exit(1); }
// Account passwords always follow the strong rule here, whatever the setting says.
if (($problem = Security::passwordProblem($password, (string)$account['username'], true)) !== null) { fwrite(STDERR, "$problem. Nothing was changed.\n"); exit(1); }

MySQLRepository::setPassword((int)$account['id'], $password);
MySQLRepository::log(null, 'PASSWORD_RESET', "Password of {$account['username']} was set from the server console", 'user', (string)$account['id']);
echo "Password updated for {$account['username']}.\n";
