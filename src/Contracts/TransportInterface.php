<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Contracts;

interface TransportInterface
{
    /**
     * @param array<string, string> $headers
     * @param array<string, mixed> $payload
     */
    public function send(
        string $url,
        array $headers,
        array $payload,
        float $timeout,
        int $attempts,
        string $method = 'POST',
        string $apiKey = ''
    ): mixed;
}
