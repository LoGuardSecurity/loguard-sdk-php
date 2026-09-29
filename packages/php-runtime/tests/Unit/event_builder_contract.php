<?php

declare(strict_types=1);

require __DIR__ . '/../../src/EventBuilder.php';

use LoGuard\Runtime\EventBuilder;

function eventCheck(
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

$builder = new EventBuilder(
    'production',
    'AID Wallet',
    65536
);

$event = $builder->build(array(
    'type' => ' HTTP_REQUEST ',
    'ip' => ' 127.0.0.1 ',
    'path' => 'login',
    'status_code' => 200,
    'user_id' => '42',
    'meta' => array(
        'method' => 'POST',
    ),
));

eventCheck(
    is_array($event),
    'valid event built'
);

eventCheck(
    $event['type'] === 'http_request',
    'type normalized'
);

eventCheck(
    $event['ip'] === '127.0.0.1',
    'ip normalized'
);

eventCheck(
    $event['path'] === '/login',
    'path normalized'
);

eventCheck(
    $event['service'] === 'aid wallet',
    'service normalized'
);

eventCheck(
    $event['user_id'] === '42',
    'user id preserved'
);

eventCheck(
    isset($event['meta']['env'])
    && $event['meta']['env'] === 'production',
    'environment added'
);

eventCheck(
    isset($event['ts'])
    && is_string($event['ts'])
    && $event['ts'] !== '',
    'timestamp added'
);

eventCheck(
    $builder->build(array(
        'type' => '',
        'ip' => '127.0.0.1',
        'path' => '/',
        'status_code' => 200,
    )) === null,
    'empty type rejected'
);

eventCheck(
    $builder->build(array(
        'type' => 'http_request',
        'ip' => '',
        'path' => '/',
        'status_code' => 200,
    )) === null,
    'empty ip rejected'
);

eventCheck(
    $builder->build(array(
        'type' => 'http_request',
        'ip' => '127.0.0.1',
        'path' => '/',
        'status_code' => 99,
    )) === null,
    'invalid status rejected'
);

$smallBuilder = new EventBuilder(
    'production',
    'test',
    128
);

eventCheck(
    $smallBuilder->build(array(
        'type' => 'http_request',
        'ip' => '127.0.0.1',
        'path' => '/',
        'status_code' => 200,
        'meta' => array(
            'q' => str_repeat('A', 1000),
        ),
    )) === null,
    'oversized event rejected'
);

echo
    'PHP RUNTIME EVENT BUILDER CONTRACT: PASS'
    . PHP_EOL;
