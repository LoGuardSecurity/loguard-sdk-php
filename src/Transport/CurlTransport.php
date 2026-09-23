<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Transport;

use LoGuard\Sdk\Contracts\TransportInterface;
use LoGuard\Sdk\Transport;

final class CurlTransport implements TransportInterface
{
    public function send(
        string $url,
        array $headers,
        array $payload,
        float $timeout,
        int $attempts,
        string $method = 'POST',
        string $apiKey = ''
    ): mixed {
        return Transport::sendSync($url, $headers, $payload, $timeout, $attempts, $method, $apiKey);
    }
}
