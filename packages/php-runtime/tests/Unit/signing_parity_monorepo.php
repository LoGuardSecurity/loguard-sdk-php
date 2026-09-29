<?php

declare(strict_types=1);

require __DIR__
    . '/../../src/Delivery/Signing.php';

require __DIR__
    . '/../../../../src/Signing.php';

use LoGuard\Runtime\Delivery\Signing as RuntimeSigning;
use LoGuard\Sdk\Signing as SdkSigning;

function parityCheck(
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

$key = 'test-api-key';

$payload = array(
    'events' => array(
        array(
            'type' => 'http_request',
            'ip' => '127.0.0.1',
            'path' => '/parity',
            'status_code' => 200,
            'ts' => '2026-09-30T00:00:00+00:00',
            'user_id' => null,
            'service' => 'runtime-test',
            'meta' => array(
                'method' => 'GET',
                'query' => array(
                    'q' => 'test',
                ),
            ),
        ),
    ),
);

$runtimeBody =
    RuntimeSigning::buildBody($payload);

$sdkBody =
    SdkSigning::buildBody($payload);

parityCheck(
    $runtimeBody === $sdkBody,
    'runtime JSON bytes match full SDK'
);

$sdkHeaders =
    SdkSigning::sign(
        $key,
        $sdkBody
    );

$timestamp =
    (int) $sdkHeaders[
        'X-LoGuard-Timestamp'
    ];

$runtimeHeaders =
    RuntimeSigning::sign(
        $key,
        $runtimeBody,
        $timestamp,
        '00000000-0000-4000-8000-000000000000'
    );

parityCheck(
    $runtimeHeaders[
        'X-LoGuard-Signature'
    ]
    ===
    $sdkHeaders[
        'X-LoGuard-Signature'
    ],
    'runtime HMAC matches full SDK'
);

echo 'PHP RUNTIME SIGNING PARITY: PASS'
    . PHP_EOL;
