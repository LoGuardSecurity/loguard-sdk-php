<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;
use LoGuard\Sdk\Contracts\TransportInterface;
use LoGuard\Sdk\Dispatch\FileSpool;
use LoGuard\Sdk\Dispatch\SpoolWorker;
use LoGuard\Sdk\Event;
use PHPUnit\Framework\TestCase;

final class SpoolWorkerTest extends TestCase
{
    public function testCompletesFullyAcceptedBatch(): void
    {
        [$worker, $spool, $directory] = $this->worker(
            ['ok' => true, 'accepted' => 2, 'dropped' => 0, 'alerts' => []],
            2
        );

        try {
            $result = $worker->runOnceResult();

            $this->assertSame(2, $result->processed);
            $this->assertSame(2, $result->accepted);
            $this->assertSame(0, $result->dropped);
            $this->assertSame([], $spool->claim());
        } finally {
            $this->cleanup($directory);
        }
    }

    public function testCompletesBatchWithPolicyDrops(): void
    {
        [$worker, $spool, $directory] = $this->worker(
            ['ok' => true, 'accepted' => 1, 'dropped' => 1, 'alerts' => []],
            2
        );

        try {
            $result = $worker->runOnceResult();

            $this->assertSame(2, $result->processed);
            $this->assertSame(1, $result->accepted);
            $this->assertSame(1, $result->dropped);
            $this->assertSame([], $spool->claim());
        } finally {
            $this->cleanup($directory);
        }
    }

    public function testRetainsBatchWhenResponseCountsDoNotMatch(): void
    {
        [$worker, $spool, $directory] = $this->worker(
            ['ok' => true, 'accepted' => 1, 'dropped' => 0, 'alerts' => []],
            2
        );

        try {
            try {
                $worker->runOnceResult();
                $this->fail('Expected an inconsistent ingest result to fail');
            } catch (\RuntimeException $exception) {
                $this->assertStringContainsString(
                    'ingest result mismatch',
                    $exception->getMessage()
                );
            }

            $claimed = $spool->claim();
            $this->assertCount(2, $claimed);
            $spool->complete($claimed, true);
        } finally {
            $this->cleanup($directory);
        }
    }

    public function testEmptySpoolProducesEmptyResult(): void
    {
        [$worker, , $directory] = $this->worker(
            ['ok' => true, 'accepted' => 0, 'dropped' => 0, 'alerts' => []],
            0
        );

        try {
            $result = $worker->runOnceResult();

            $this->assertSame(0, $result->processed);
            $this->assertSame(0, $result->accepted);
            $this->assertSame(0, $result->dropped);
        } finally {
            $this->cleanup($directory);
        }
    }

    /**
     * @param array<string, mixed> $response
     * @return array{SpoolWorker, FileSpool, string}
     */
    private function worker(array $response, int $eventCount): array
    {
        $directory = sys_get_temp_dir()
            . '/loguard-worker-test-'
            . bin2hex(random_bytes(6));

        $spool = new FileSpool($directory, 10);

        for ($index = 0; $index < $eventCount; $index++) {
            $spool->enqueue(new Event(
                'http_request',
                '127.0.0.1',
                '/test',
                500,
                date(DATE_ATOM)
            ));
        }

        $transport = new class ($response) implements TransportInterface {
            /** @param array<string, mixed> $response */
            public function __construct(private readonly array $response)
            {
            }

            public function send(
                string $url,
                array $headers,
                array $payload,
                float $timeout,
                int $attempts,
                string $method = 'POST',
                string $apiKey = ''
            ): mixed {
                return $this->response;
            }
        };

        $client = new Client(new Config('lg_test'), $transport);

        return [new SpoolWorker($client, $spool), $spool, $directory];
    }

    private function cleanup(string $directory): void
    {
        foreach (glob($directory . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($directory);
    }
}
