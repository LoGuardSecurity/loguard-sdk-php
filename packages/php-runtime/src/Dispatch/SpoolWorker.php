<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Dispatch;

use LoGuard\Runtime\Delivery\TransportInterface;

final class SpoolWorker
{
    /** @var TransportInterface */
    private $transport;

    /** @var FileSpool */
    private $spool;

    public function __construct(
        TransportInterface $transport,
        FileSpool $spool
    ) {
        $this->transport = $transport;
        $this->spool = $spool;
    }

    public function runOnceResult(
        int $batchSize = 50
    ): SpoolRunResult {
        $events = $this->spool->claim(
            min(
                50,
                max(1, $batchSize)
            )
        );

        if ($events === array()) {
            return new SpoolRunResult(
                0,
                0,
                0
            );
        }

        $payload = array();

        foreach ($events as $event) {
            unset($event['__spool_file']);
            $payload[] = $event;
        }

        try {
            $result = $this->transport->send(
                $payload
            );

            $processed =
                $result->accepted
                + $result->dropped;

            if (!$result->ok) {
                throw new \RuntimeException(
                    'ingest returned ok=false'
                );
            }

            if (
                $processed
                !== count($events)
            ) {
                throw new \RuntimeException(
                    sprintf(
                        'ingest result mismatch: sent=%d accepted=%d dropped=%d',
                        count($events),
                        $result->accepted,
                        $result->dropped
                    )
                );
            }

            $this->spool->complete(
                $events,
                true
            );

            return new SpoolRunResult(
                $processed,
                $result->accepted,
                $result->dropped
            );
        } catch (\Throwable $e) {
            $this->spool->complete(
                $events,
                false
            );

            throw $e;
        }
    }
}
