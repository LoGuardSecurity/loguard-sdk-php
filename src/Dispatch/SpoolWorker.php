<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Dispatch;

use LoGuard\Sdk\Client;

final class SpoolWorker
{
    public function __construct(private readonly Client $client, private readonly FileSpool $spool)
    {
    }

    public function runOnce(int $batchSize = 50): int
    {
        return $this->runOnceResult($batchSize)->processed;
    }

    public function runOnceResult(int $batchSize = 50): SpoolRunResult
    {
        $events = $this->spool->claim(min(50, max(1, $batchSize)));
        if ($events === []) {
            return new SpoolRunResult(0, 0, 0);
        }

        $payload = array_map(static function (array $event): array {
            unset($event['__spool_file']);
            return $event;
        }, $events);

        try {
            $result = $this->client->eventBatch($payload);
            $processed = $result->inserted + $result->dropped;

            if (!$result->ok) {
                throw new \RuntimeException('ingest returned ok=false');
            }

            if ($processed !== count($events)) {
                throw new \RuntimeException(
                    sprintf(
                        'ingest result mismatch: sent=%d accepted=%d dropped=%d',
                        count($events),
                        $result->inserted,
                        $result->dropped
                    )
                );
            }

            $this->spool->complete($events, true);

            return new SpoolRunResult(
                $processed,
                $result->inserted,
                $result->dropped
            );
        } catch (\Throwable $e) {
            $this->spool->complete($events, false);
            throw $e;
        }
    }
}
