<?php

declare(strict_types=1);

require __DIR__
    . '/../../src/Dispatch/FileSpool.php';

require __DIR__
    . '/../../src/Delivery/IngestResult.php';

require __DIR__
    . '/../../src/Delivery/TransportInterface.php';

require __DIR__
    . '/../../src/Delivery/Signing.php';

require __DIR__
    . '/../../src/Dispatch/SpoolRunResult.php';

require __DIR__
    . '/../../src/Dispatch/SpoolWorker.php';

use LoGuard\Runtime\Delivery\IngestResult;
use LoGuard\Runtime\Delivery\Signing;
use LoGuard\Runtime\Delivery\TransportInterface;
use LoGuard\Runtime\Dispatch\FileSpool;
use LoGuard\Runtime\Dispatch\SpoolWorker;

function deliveryCheck(
    $condition,
    string $message
): void {
    if (!$condition) {
        fwrite(
            STDERR,
            'FAIL: '
            . $message
            . PHP_EOL
        );

        exit(1);
    }

    echo 'PASS: '
        . $message
        . PHP_EOL;
}

function deliveryCleanup(
    string $directory
): void {
    foreach (
        glob($directory . '/*')
        ?: array()
        as $path
    ) {
        @unlink($path);
    }

    @rmdir($directory);
}

function deliveryEvent(
    string $path
): array {
    return array(
        'type' => 'http_request',
        'ip' => '127.0.0.1',
        'path' => $path,
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
    );
}

final class SuccessTransport
    implements TransportInterface
{
    public function send(
        array $events
    ): IngestResult {
        return new IngestResult(
            true,
            count($events),
            0
        );
    }
}

final class FailureTransport
    implements TransportInterface
{
    public function send(
        array $events
    ): IngestResult {
        throw new RuntimeException(
            'simulated transport failure'
        );
    }
}

final class FalseResultTransport
    implements TransportInterface
{
    public function send(
        array $events
    ): IngestResult {
        return new IngestResult(
            false,
            count($events),
            0
        );
    }
}

final class MismatchTransport
    implements TransportInterface
{
    public function send(
        array $events
    ): IngestResult {
        return new IngestResult(
            true,
            0,
            0
        );
    }
}

/*
 * Signing protocol contract.
 */

$key = 'test-api-key';
$timestamp = 1759190400;
$requestId = '00000000-0000-4000-8000-000000000000';

$payload = array(
    'events' => array(
        deliveryEvent('/signing'),
    ),
);

$body = Signing::buildBody($payload);

$expectedBody = json_encode(
    $payload,
    JSON_UNESCAPED_SLASHES
    | JSON_UNESCAPED_UNICODE
    | JSON_THROW_ON_ERROR
);

deliveryCheck(
    $body === $expectedBody,
    'runtime JSON bytes are deterministic'
);

$headers = Signing::sign(
    $key,
    $body,
    $timestamp,
    $requestId
);

$expectedSignature =
    'sha256='
    . hash_hmac(
        'sha256',
        $timestamp
        . '.'
        . $body,
        $key
    );

deliveryCheck(
    $headers['X-LoGuard-Signature']
    === $expectedSignature,
    'signature covers exact timestamp.body bytes'
);

deliveryCheck(
    $headers['X-LoGuard-Timestamp']
    === (string) $timestamp,
    'signing timestamp preserved'
);

deliveryCheck(
    $headers['X-Request-ID']
    === $requestId,
    'request id preserved'
);

deliveryCheck(
    $headers['X-Api-Key']
    === $key,
    'api key header preserved'
);

/*
 * Success removes claimed file.
 */

$successDir =
    sys_get_temp_dir()
    . '/loguard-runtime-delivery-success-'
    . bin2hex(random_bytes(6));

try {
    $spool = new FileSpool(
        $successDir,
        10
    );

    deliveryCheck(
        $spool->enqueue(
            deliveryEvent('/success')
        ),
        'success event enqueued'
    );

    $result = (
        new SpoolWorker(
            new SuccessTransport(),
            $spool
        )
    )->runOnceResult(50);

    deliveryCheck(
        $result->processed === 1
        && $result->accepted === 1
        && $result->dropped === 0,
        'successful delivery result preserved'
    );

    deliveryCheck(
        count(
            glob(
                $successDir . '/*.json'
            ) ?: array()
        ) === 0,
        'successful delivery removes spool event'
    );
} finally {
    deliveryCleanup($successDir);
}

/*
 * Transport failure requeues.
 */

$failureDir =
    sys_get_temp_dir()
    . '/loguard-runtime-delivery-failure-'
    . bin2hex(random_bytes(6));

try {
    $spool = new FileSpool(
        $failureDir,
        10
    );

    $spool->enqueue(
        deliveryEvent('/failure')
    );

    $thrown = false;

    try {
        (
            new SpoolWorker(
                new FailureTransport(),
                $spool
            )
        )->runOnceResult(50);
    } catch (RuntimeException $e) {
        $thrown = true;
    }

    deliveryCheck(
        $thrown,
        'transport failure propagated'
    );

    deliveryCheck(
        count(
            glob(
                $failureDir . '/*.json'
            ) ?: array()
        ) === 1,
        'transport failure requeues event'
    );
} finally {
    deliveryCleanup($failureDir);
}

/*
 * ok=false requeues.
 */

$falseDir =
    sys_get_temp_dir()
    . '/loguard-runtime-delivery-false-'
    . bin2hex(random_bytes(6));

try {
    $spool = new FileSpool(
        $falseDir,
        10
    );

    $spool->enqueue(
        deliveryEvent('/false')
    );

    $thrown = false;

    try {
        (
            new SpoolWorker(
                new FalseResultTransport(),
                $spool
            )
        )->runOnceResult(50);
    } catch (RuntimeException $e) {
        $thrown = true;
    }

    deliveryCheck(
        $thrown,
        'ok=false rejected'
    );

    deliveryCheck(
        count(
            glob(
                $falseDir . '/*.json'
            ) ?: array()
        ) === 1,
        'ok=false requeues event'
    );
} finally {
    deliveryCleanup($falseDir);
}

/*
 * Count mismatch requeues.
 */

$mismatchDir =
    sys_get_temp_dir()
    . '/loguard-runtime-delivery-mismatch-'
    . bin2hex(random_bytes(6));

try {
    $spool = new FileSpool(
        $mismatchDir,
        10
    );

    $spool->enqueue(
        deliveryEvent('/mismatch')
    );

    $thrown = false;

    try {
        (
            new SpoolWorker(
                new MismatchTransport(),
                $spool
            )
        )->runOnceResult(50);
    } catch (RuntimeException $e) {
        $thrown = true;
    }

    deliveryCheck(
        $thrown,
        'ingest count mismatch rejected'
    );

    deliveryCheck(
        count(
            glob(
                $mismatchDir . '/*.json'
            ) ?: array()
        ) === 1,
        'count mismatch requeues event'
    );
} finally {
    deliveryCleanup($mismatchDir);
}

echo 'PHP RUNTIME DELIVERY CONTRACT: PASS'
    . PHP_EOL;
