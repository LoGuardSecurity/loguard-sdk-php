<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Dispatch;

final class SpoolRunResult
{
    public function __construct(
        public readonly int $processed,
        public readonly int $accepted,
        public readonly int $dropped
    ) {
    }
}
