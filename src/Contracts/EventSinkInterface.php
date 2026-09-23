<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Contracts;

use LoGuard\Sdk\Event;

interface EventSinkInterface
{
    public function enqueue(Event $event): bool;
}
