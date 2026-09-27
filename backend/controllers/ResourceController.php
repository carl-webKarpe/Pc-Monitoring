<?php
declare(strict_types=1);

require_once __DIR__ . '/../repositories/MySQLRepository.php'; require_once __DIR__ . '/../helpers/Response.php'; require_once __DIR__ . '/../helpers/Validation.php'; require_once __DIR__ . '/../middleware/RoleMiddleware.php';
final class ResourceController {
    public static function list(string $resource, array $roles): never { RoleMiddleware::allow($roles); Response::success('Request successful', MySQLRepository::resource($resource)); }
    public static function show(string $resource, string $id, array $roles): never { RoleMiddleware::allow($roles); $item = MySQLRepository::find($resource, Validation::id($id)); if (!$item) Response::error('Resource not found', 'NOT_FOUND', 404); Response::success('Request successful', $item); }
    public static function collection(string $resource, array $roles, int $status = 200): never { RoleMiddleware::allow($roles); $data = Validation::body(); Validation::resource($data, $resource); Response::success('Resource saved', MySQLRepository::create($resource, $data), $status); }
    public static function update(string $resource, string $id, array $roles): never { RoleMiddleware::allow($roles); $validatedId = Validation::id($id); if (!MySQLRepository::find($resource, $validatedId)) Response::error('Resource not found', 'NOT_FOUND', 404); Response::success('Resource updated', MySQLRepository::update($resource, $validatedId, Validation::body())); }
    public static function delete(string $resource, string $id): never { RoleMiddleware::allow(['Super Admin']); $validatedId = Validation::id($id); if (!MySQLRepository::find($resource, $validatedId)) Response::error('Resource not found', 'NOT_FOUND', 404); if ($resource === 'admins' && $validatedId === 1) Response::error('Primary Super Admin cannot be removed', 'PRIMARY_ADMIN_PROTECTED', 403); MySQLRepository::delete($resource, $validatedId); Response::success('Resource deleted', null); }
}
