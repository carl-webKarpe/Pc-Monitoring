<?php
declare(strict_types=1);

require_once __DIR__ . '/../repositories/MySQLRepository.php'; require_once __DIR__ . '/../helpers/Response.php'; require_once __DIR__ . '/../helpers/Validation.php'; require_once __DIR__ . '/../middleware/RoleMiddleware.php';
final class ResourceController {
    public static function list(string $resource, array $roles): never { RoleMiddleware::allow($roles); Response::success('Request successful', MySQLRepository::resource($resource)); }
    public static function show(string $resource, string $id, array $roles): never { RoleMiddleware::allow($roles); $item = MySQLRepository::find($resource, Validation::id($id)); if (!$item) Response::error('Resource not found', 'NOT_FOUND', 404); Response::success('Request successful', $item); }
    public static function collection(string $resource, array $roles, int $status = 200): never { RoleMiddleware::allow($roles); $data = Validation::body(); Validation::resource($data, $resource); Response::success('Resource saved', self::guardDuplicates(fn() => MySQLRepository::create($resource, $data)), $status); }
    public static function update(string $resource, string $id, array $roles): never
    {
        $user = RoleMiddleware::allow($roles);
        $validatedId = Validation::id($id);
        if (!MySQLRepository::find($resource, $validatedId)) Response::error('Resource not found', 'NOT_FOUND', 404);
        $data = Validation::body();
        Validation::resource($data, $resource, true);
        if (isset($data['status']) && $data['status'] !== 'Active' && ($validatedId === 1 || $validatedId === (int)$user['id'])) Response::error('This account cannot be deactivated', 'ACCOUNT_PROTECTED', 403);
        Response::success('Resource updated', self::guardDuplicates(fn() => MySQLRepository::update($resource, $validatedId, $data)));
    }
    public static function delete(string $resource, string $id): never
    {
        $user = RoleMiddleware::allow(['Super Admin']);
        $validatedId = Validation::id($id);
        if (!MySQLRepository::find($resource, $validatedId)) Response::error('Resource not found', 'NOT_FOUND', 404);
        if ($validatedId === 1 || $validatedId === (int)$user['id']) Response::error('This account cannot be removed', 'ACCOUNT_PROTECTED', 403);
        if (!MySQLRepository::delete($resource, $validatedId)) Response::error('Super Admin accounts cannot be removed', 'ACCOUNT_PROTECTED', 403);
        Response::success('Resource deleted', null);
    }

    private static function guardDuplicates(callable $write): array
    {
        try { return $write(); }
        catch (PDOException $exception) { if ($exception->getCode() === '23000') Response::error('Email or username is already in use', 'DUPLICATE_ACCOUNT', 409); throw $exception; }
    }
}
