<?php

declare(strict_types=1);

$root = __DIR__ . '/../../src/Http/';

require $root . 'FieldCaptureResult.php';
require $root . 'FieldPolicy.php';
require $root . 'RequestContext.php';
require $root . 'CapturePolicy.php';
require $root . 'HeaderPolicy.php';
require $root . 'ClientIp.php';
require $root . 'HttpEventFactory.php';

use LoGuard\Runtime\Http\CapturePolicy;
use LoGuard\Runtime\Http\HttpEventFactory;
use LoGuard\Runtime\Http\RequestContext;

function httpCheck(
    $condition,
    string $message
): void {
    if (!$condition) {
        fwrite(
            STDERR,
            'FAIL: ' . $message . PHP_EOL
        );
        exit(1);
    }

    echo 'PASS: ' . $message . PHP_EOL;
}

$factory = new HttpEventFactory();

$context = new RequestContext(
    'post',
    'search',
    200,
    '10.0.0.10',
    '198.51.100.44, 10.0.0.10',
    null,
    '42',
    array(
        'User-Agent' => 'runtime-test',
        'Authorization' => 'DO-NOT-STORE',
        'Cookie' => 'session=DO-NOT-STORE',
    ),
    array(
        'q' => "' OR 1=1--",
        'password' => 'DO-NOT-STORE',
    ),
    '{"search":"<script>alert(1)</script>","token":"DO-NOT-STORE"}',
    'application/json'
);

$policy = new CapturePolicy(
    array(),
    false,
    array(
        'user-agent',
        'authorization',
        'cookie',
    ),
    array(),
    array(),
    array('10.0.0.0/8'),
    32768,
    8,
    true
);

$event = $factory->create(
    $context,
    $policy
);

httpCheck(
    is_array($event),
    '200 request captured in security mode'
);

httpCheck(
    $event['path'] === '/search',
    'path normalized'
);

httpCheck(
    $event['status_code'] === 200,
    'status preserved'
);

httpCheck(
    $event['user_id'] === '42',
    'user id preserved'
);

httpCheck(
    $event['ip'] === '198.51.100.44',
    'trusted proxy chain resolves client IP'
);

httpCheck(
    isset($event['meta']['query']['q']),
    'security query captured'
);

httpCheck(
    !isset($event['meta']['query']['password']),
    'query password stripped'
);

httpCheck(
    isset($event['meta']['body']['search']),
    'security JSON body captured'
);

httpCheck(
    !isset($event['meta']['body']['token']),
    'body token stripped'
);

httpCheck(
    isset(
        $event['meta']['headers']['user-agent']
    ),
    'requested safe header captured'
);

httpCheck(
    !isset(
        $event['meta']['headers']['authorization']
    ),
    'Authorization never captured'
);

httpCheck(
    !isset(
        $event['meta']['headers']['cookie']
    ),
    'Cookie never captured'
);

$spoofed = $factory->create(
    new RequestContext(
        'GET',
        '/test',
        200,
        '203.0.113.10',
        '1.2.3.4'
    ),
    new CapturePolicy(
        array(),
        false,
        array(),
        array(),
        array(),
        array('10.0.0.0/8'),
        32768,
        8,
        true
    )
);

httpCheck(
    $spoofed['ip'] === '203.0.113.10',
    'untrusted peer cannot spoof X-Forwarded-For'
);

$legacyFiltered = $factory->create(
    new RequestContext(
        'GET',
        '/legacy',
        200,
        '127.0.0.1'
    ),
    new CapturePolicy()
);

httpCheck(
    $legacyFiltered === null,
    'default non-security policy still filters status 200'
);

echo
    'PHP RUNTIME HTTP EVENT CONTRACT: PASS'
    . PHP_EOL;
