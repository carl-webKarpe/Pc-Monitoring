<?php
declare(strict_types=1);

final class Response
{
    public static function json(bool $success, string $message, mixed $data = null, int $status = 200, array $errors = []): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        $payload = ['success' => $success, 'message' => $message];
        if ($success) $payload['data'] = $data;
        if ($errors !== []) $payload['errors'] = $errors;
        echo json_encode($payload, JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function success(string $message, mixed $data = null, int $status = 200): never { self::json(true, $message, $data, $status); }
    public static function error(string $message, string $code, int $status = 400, array $errors = []): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        $payload = ['success' => false, 'message' => $message, 'error' => ['code' => $code]];
        if ($errors !== []) $payload['errors'] = $errors;
        echo json_encode($payload, JSON_UNESCAPED_SLASHES);
        exit;
    }
}
