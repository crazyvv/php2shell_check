<?php
/* Include ONLY after authorization in your existing internal admin route:
 * define('PHP_SELFCHECK_AUTHORIZED', true);
 * require '/path/to/web-runtime-report.php';
 * Do not deploy this as a public diagnostic endpoint. */
if (!defined('PHP_SELFCHECK_AUTHORIZED') || PHP_SELFCHECK_AUTHORIZED !== true) {
    http_response_code(403);
    exit;
}
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
$settings = [];
foreach (['session.upload_progress.enabled', 'file_uploads', 'enable_post_data_reading',
          'memory_limit', 'post_max_size', 'upload_max_filesize', 'max_file_uploads',
          'max_multipart_body_parts', 'fatal_error_backtraces'] as $key) {
    $value = ini_get($key);
    $settings[$key] = $value === false ? null : $value;
}
echo json_encode([
    'schema' => 'php-selfcheck-host/v1',
    'source' => 'developer_supplied_unverified',
    'collected_at' => gmdate('c'),
    'runtime_observations' => [[
        'scope' => 'web_runtime', 'sapi' => PHP_SAPI, 'version' => PHP_VERSION,
        'settings' => $settings,
    ]],
    'limitations' => ['仅覆盖当前请求命中的实例；报告未签名，实例归属需人工核验。'],
], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
