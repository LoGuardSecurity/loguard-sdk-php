<?php
/**
 * Minimal router for `php -S` used by TransportIntegrationTest.
 * Behavior is selected by the request path so each test scenario is
 * a plain HTTP call, no test framework coupling needed here.
 */

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Tracks how many times a given attempt-counter route has been hit,
// across the lifetime of this server process, using a file in the
// system temp dir (each PHP dev-server request is its own process).
function hit_count(string $key): int
{
    $file = sys_get_temp_dir() . '/loguard_mock_' . md5($key) . '.count';
    $n = 1;
    if (is_file($file)) {
        $n = (int) file_get_contents($file) + 1;
    }
    file_put_contents($file, (string) $n);
    return $n;
}

header('Content-Type: application/json');

switch ($path) {
    case '/v1/ingest/ok':
        echo json_encode(['ok' => true, 'accepted' => 1, 'dropped' => 0, 'alerts' => [], 'plan' => 'pro', 'usage' => ['used' => 1, 'limit' => 100, 'month' => '2026-09']]);
        break;

    case '/v1/ingest/fail-twice-then-ok':
        $n = hit_count('fail-twice-then-ok');
        if ($n < 3) {
            http_response_code(503);
            echo json_encode(['detail' => 'temporarily unavailable']);
        } else {
            http_response_code(200);
            echo json_encode(['ok' => true, 'accepted' => 1, 'dropped' => 0, 'alerts' => [], 'plan' => 'pro', 'usage' => []]);
        }
        break;

    case '/v1/ingest/always-500':
        http_response_code(500);
        echo json_encode(['detail' => 'internal error']);
        break;

    case '/v1/ingest/unauthorized':
        http_response_code(401);
        echo json_encode(['detail' => 'invalid api key']);
        break;

    case '/v1/ingest/quota':
        http_response_code(429);
        echo json_encode(['detail' => ['err' => 'usage_limit_exceeded', 'used' => 1000, 'limit' => 1000, 'plan' => 'free']]);
        break;

    case '/v1/ingest/malformed-json':
        http_response_code(200);
        echo '{not valid json!!';
        break;

    case '/v1/ingest/oversized':
        http_response_code(200);
        // Larger than Transport::MAX_RESPONSE_BYTES -- must not exhaust client memory.
        echo str_repeat('a', 6 * 1024 * 1024);
        break;

    case '/v1/ingest/redirect':
        http_response_code(302);
        header('Location: https://attacker.example/steal');
        break;

    case '/v1/ingest':
    case '/v1/ingest/capture':
        // Records the raw request body so a test can assert on exactly
        // what the SDK/middleware actually sent, end-to-end over real
        // HTTP -- not a reconstruction of what the code "should" send.
        file_put_contents(sys_get_temp_dir() . '/loguard_mock_capture.json', file_get_contents('php://input'));
        echo json_encode(['ok' => true, 'accepted' => 1, 'dropped' => 0, 'alerts' => [], 'plan' => 'pro', 'usage' => []]);
        break;

    default:
        http_response_code(404);
        echo json_encode(['detail' => 'unknown mock route']);
}
