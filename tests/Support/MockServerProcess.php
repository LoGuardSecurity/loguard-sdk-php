<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Support;

/**
 * Spins up `php -S 127.0.0.1:<port>` against router.php for
 * transport-level integration tests: real HTTP over loopback, real
 * cURL, real retry/backoff timing -- not mocked at the PHP level.
 */
final class MockServerProcess
{
    /** @var resource|null */
    private $process;
    private int $port;

    public function __construct()
    {
        $this->port = random_int(20000, 60000);
        $docroot = __DIR__ . '/mock-server';
        $cmd = sprintf(
            'php -S 127.0.0.1:%d -t %s %s/router.php',
            $this->port,
            escapeshellarg($docroot),
            escapeshellarg($docroot)
        );

        $this->process = proc_open($cmd, [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);

        // Give the dev server a moment to bind before the first request.
        $deadline = microtime(true) + 3.0;
        while (microtime(true) < $deadline) {
            $conn = @fsockopen('127.0.0.1', $this->port, $errno, $errstr, 0.1);
            if ($conn) {
                fclose($conn);
                break;
            }
            usleep(50_000);
        }
    }

    public function baseUrl(): string
    {
        return 'http://127.0.0.1:' . $this->port;
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
            $this->process = null;
        }
    }

    public function __destruct()
    {
        $this->stop();
    }
}
