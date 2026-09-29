<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Delivery;

interface TransportInterface
{
    /**
     * @param array<int, array<string, mixed>> $events
     */
    public function send(array $events): IngestResult;
}
