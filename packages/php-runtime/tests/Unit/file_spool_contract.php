<?php

declare(strict_types=1);

require __DIR__
    . '/../../src/Dispatch/FileSpool.php';

use LoGuard\Runtime\Dispatch\FileSpool;

function spoolCheck(
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

function cleanupSpool(string $directory): void
{
    foreach (
        glob($directory . '/*')
        ?: array()
        as $path
    ) {
        @unlink($path);
    }

    @rmdir($directory);
}

function testEvent(string $path): array
{
    return array(
        'type' => 'http_request',
        'ip' => '127.0.0.1',
        'path' => $path,
        'status_code' => 200,
        'ts' => date(DATE_ATOM),
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

$directory = sys_get_temp_dir()
    . '/loguard-runtime-spool-'
    . bin2hex(random_bytes(6));

try {
    $spool = new FileSpool(
        $directory,
        2
    );

    spoolCheck(
        $spool->enqueue(testEvent('/one')),
        'first event enqueued'
    );

    spoolCheck(
        is_dir($directory),
        'spool directory created'
    );

    $files = glob(
        $directory . '/*.json'
    ) ?: array();

    spoolCheck(
        count($files) === 1,
        'one ready spool file exists'
    );

    if (DIRECTORY_SEPARATOR === '/') {
        $mode = fileperms($files[0]);

        spoolCheck(
            $mode !== false
            && (($mode & 0777) === 0600),
            'spool file mode is 0600'
        );

        $directoryMode = fileperms($directory);

        spoolCheck(
            $directoryMode !== false
            && (($directoryMode & 0777) === 0700),
            'spool directory mode is 0700'
        );
    }

    $raw = file_get_contents($files[0]);

    spoolCheck(
        is_string($raw),
        'spool file readable'
    );

    $decoded = json_decode(
        (string) $raw,
        true
    );

    spoolCheck(
        is_array($decoded),
        'spool JSON valid'
    );

    spoolCheck(
        isset($decoded['path'])
        && $decoded['path'] === '/one',
        'wire event path preserved'
    );

    spoolCheck(
        isset($decoded['meta']['method'])
        && $decoded['meta']['method'] === 'GET',
        'wire meta preserved'
    );

    spoolCheck(
        substr((string) $raw, -1) === "\n",
        'wire body has canonical trailing newline'
    );

    $claimed = $spool->claim();

    spoolCheck(
        count($claimed) === 1,
        'event claimed'
    );

    spoolCheck(
        isset($claimed[0]['__spool_file']),
        'claim carries private spool marker'
    );

    spoolCheck(
        glob($directory . '/*.json')
            === array(),
        'ready file atomically moved while claimed'
    );

    $spool->complete(
        $claimed,
        false
    );

    spoolCheck(
        count(
            glob($directory . '/*.json')
            ?: array()
        ) === 1,
        'failed delivery returns event to queue'
    );

    $claimed = $spool->claim();

    spoolCheck(
        count($claimed) === 1,
        'returned event claimable again'
    );

    $spool->complete(
        $claimed,
        true
    );

    spoolCheck(
        glob($directory . '/*')
            === array(),
        'successful delivery removes claimed file'
    );

    spoolCheck(
        $spool->enqueue(testEvent('/limit-1')),
        'limit event one accepted'
    );

    spoolCheck(
        $spool->enqueue(testEvent('/limit-2')),
        'limit event two accepted'
    );

    spoolCheck(
        !$spool->enqueue(testEvent('/limit-3')),
        'max-files limit enforced'
    );

    cleanupSpool($directory);

    $directory = sys_get_temp_dir()
        . '/loguard-runtime-spool-'
        . bin2hex(random_bytes(6));

    @mkdir($directory, 0700, true);

    $bad = $directory
        . '/00000000000000000001-bad.json';

    file_put_contents(
        $bad,
        '{"broken":'
    );

    $spool = new FileSpool(
        $directory,
        10
    );

    $claimed = $spool->claim();

    spoolCheck(
        $claimed === array(),
        'malformed JSON never returned to worker'
    );

    spoolCheck(
        file_exists($bad),
        'malformed JSON retained for later recovery'
    );

    cleanupSpool($directory);

    echo
        'PHP RUNTIME FILE SPOOL CONTRACT: PASS'
        . PHP_EOL;
} finally {
    cleanupSpool($directory);
}
