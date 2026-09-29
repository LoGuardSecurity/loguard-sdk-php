<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Dispatch;

final class SpoolRunResult
{
    public $processed;
    public $accepted;
    public $dropped;

    public function __construct(
        int $processed,
        int $accepted,
        int $dropped
    ) {
        $this->processed = $processed;
        $this->accepted = $accepted;
        $this->dropped = $dropped;
    }
}
