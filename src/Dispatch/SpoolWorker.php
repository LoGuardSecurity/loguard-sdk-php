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
        $events = $this->spool->claim(min(50, max(1, $batchSize)));
        if ($events === []) {
            return 0;
        }

        $payload = array_map(static function (array $event): array {
            unset($event['__spool_file']);
            return $event;
        }, $events);

        try {
            $this->client->eventBatch($payload);
            $this->spool->complete($events, true);
            return count($events);
        } catch (\Throwable $e) {
            $this->spool->complete($events, false);
            throw $e;
        }
    }
}
