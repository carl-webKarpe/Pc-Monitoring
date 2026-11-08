<?php
declare(strict_types=1);

// Sets a new password for an MST account (use it to replace the demo passwords after installing).
// Run on the MST server from the project root:
//   php backend/tools/set-password.php superadmin
// The password is typed at the prompt (twice) and stored only as a password_hash().

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/Database.php';
require_once __DIR__ . '/../helpers/Security.php';
require_once __DIR__ . '/../repositories/MySQLRepository.php';

$login = $argv[1] ?? '';
if ($login === '') { fwrite(STDERR, "Usage: php backend/tools/set-password.php <username-or-email>\n"); exit(2); }

try {
    $account = MySQLRepository::findForLogin($login);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Could not reach the database: ' . $exception->getMessage() . "\n"); exit(1);
}
if (!$account) {
    // Say where it looked and what is there: the usual cause is .env DB_DATABASE naming another database.
    $config = mst_config();
    echo "No account found for \"$login\" in database \"{$config['db_name']}\" ({$config['db_host']}:{$config['db_port']}; set by DB_DATABASE in .env).\n";
    $accounts = Database::connection()->query('SELECT username, email, role, status FROM users ORDER BY id')->fetchAll();
    echo $accounts ? "Accounts in this database:\n" . implode('', array_map(static fn($row) => "  - {$row['username']} ({$row['email']}, {$row['role']}, {$row['status']})\n", $accounts))
        : "This database has no accounts at all.\n";
    $username = str_contains($login, '@') ? strstr($login, '@', true) : $login;
    if (!preg_match('/^[A-Za-z0-9._-]{3,40}$/', $username)) exit(2);
    $role = strtolower($username) === 'superadmin' ? 'Super Admin' : 'Admin';
    echo "Create the account \"$username\" ($role) in this database now? (y/n): ";
    if (strtolower(trim((string)fgets(STDIN))) !== 'y') { echo "Nothing was changed. To reset another account: php backend/tools/set-password.php <username>\n"; exit(2); }
    try {
        // '!' is never a valid password hash: nobody can log in until the password below is set.
        Database::connection()->prepare("INSERT INTO users (first_name, last_name, email, username, password_hash, role, status) VALUES ('System', 'Administrator', ?, ?, '!', ?, 'Active')")
            ->execute([str_contains($login, '@') ? $login : "$username@mst.local", $username, $role]);
    } catch (Throwable $exception) {
        fwrite(STDERR, 'Could not create the account: ' . $exception->getMessage() . "\n"); exit(1);
    }
    MySQLRepository::log(null, 'USER_CREATED', "Account $username ($role) was created from the server console", 'user', null);
    $account = MySQLRepository::findForLogin($username);
    echo "Account \"$username\" created. Now choose its password.\n";
}

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
