<?php
declare(strict_types=1);

require_once __DIR__ . '/../config/cors.php';
require_once __DIR__ . '/../helpers/Response.php';
require_once __DIR__ . '/../helpers/Validation.php';
require_once __DIR__ . '/../controllers/AuthController.php';
require_once __DIR__ . '/../controllers/UserController.php';
require_once __DIR__ . '/../controllers/AdminController.php';
require_once __DIR__ . '/../controllers/ComputerController.php';
require_once __DIR__ . '/../controllers/ThreatController.php';
require_once __DIR__ . '/../controllers/ScanController.php';
require_once __DIR__ . '/../controllers/ReportController.php';
require_once __DIR__ . '/../controllers/ActivityController.php';
require_once __DIR__ . '/../controllers/PermissionController.php';
require_once __DIR__ . '/../controllers/SettingsController.php';
require_once __DIR__ . '/../controllers/FileScannerController.php';

ini_set('display_errors', '0');
mst_apply_cors();
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

set_exception_handler(static function (Throwable $exception): never { error_log($exception->getMessage()); Response::error('Internal server error', 'INTERNAL_ERROR', 500); });

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = preg_replace('#^/api/?#', '', $path);
$segments = array_map('rawurldecode', array_values(array_filter(explode('/', trim($path, '/')), 'strlen')));
if ($segments === []) Response::success('MST API foundation', ['version' => '0.1.0', 'status' => 'ok']);

$resource = $segments[0] ?? '';
$id = $segments[1] ?? null;
$action = $segments[2] ?? null;

if ($resource === 'auth') {
    if ($id === 'login' && $method === 'POST') AuthController::login(Validation::body());
    if ($id === 'logout' && $method === 'POST') AuthController::logout();
    if ($id === 'me' && $method === 'GET') AuthController::me();
    Response::error('Method not allowed', 'METHOD_NOT_ALLOWED', 405);
}
if ($resource === 'users') UserController::index($method, $id);
if ($resource === 'admins') AdminController::index($method, $id);
if ($resource === 'computers') ComputerController::index($method, $id);
if ($resource === 'threats') ThreatController::index($method, $id, $action);
if ($resource === 'scans') ScanController::index($method, $id);
if ($resource === 'reports') ReportController::index($method);
if ($resource === 'activity') ActivityController::index($method);
if ($resource === 'permissions') PermissionController::index($method, $id);
if ($resource === 'settings') SettingsController::index($method);
if ($resource === 'file-scanner') FileScannerController::index($method);
Response::error('Endpoint not found', 'NOT_FOUND', 404);
