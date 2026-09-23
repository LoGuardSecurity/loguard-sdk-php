<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Http;

final class CapturePolicy
{
    /**
     * @param int[] $statuses
     * @param string[] $headers
     * @param array<string, string[]> $queryByRoute
     * @param array<string, string[]> $bodyByRoute
     * @param string[] $trustedProxies
     */
    public function __construct(
        public readonly array $statuses = [400, 401, 403, 404, 429, 500, 502, 503],
        public readonly bool $trackAll = false,
        public readonly array $headers = [],
        public readonly array $queryByRoute = [],
        public readonly array $bodyByRoute = [],
        public readonly array $trustedProxies = [],
        public readonly int $maxBodyBytes = FieldPolicy::DEFAULT_MAX_BODY_BYTES,
        public readonly int $maxJsonDepth = FieldPolicy::DEFAULT_MAX_JSON_DEPTH
    ) {
    }

    public function tracks(int $status): bool
    {
        return $this->trackAll || in_array($status, $this->statuses, true);
    }
}
