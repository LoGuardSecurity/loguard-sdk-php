<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Http;

final class RequestContext
{
    /**
     * @param array<string, string|string[]> $headers
     * @param array<string, mixed> $query
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly int $statusCode,
        public readonly string $directPeerIp,
        public readonly ?string $forwardedFor = null,
        public readonly ?string $routeName = null,
        public readonly ?string $userId = null,
        public readonly array $headers = [],
        public readonly array $query = [],
        public readonly ?string $rawBody = null,
        public readonly ?string $contentType = null
    ) {
    }
}
