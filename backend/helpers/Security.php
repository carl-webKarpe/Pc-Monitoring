<?php
declare(strict_types=1);

final class Security
{
    public static function publicUser(array $user): array { unset($user['password'], $user['passwordHash']); return $user; }
    public static function hash(string $password): string { return password_hash($password, PASSWORD_DEFAULT); }
    public static function verify(string $password, string $hash): bool { return password_verify($password, $hash); }
}
