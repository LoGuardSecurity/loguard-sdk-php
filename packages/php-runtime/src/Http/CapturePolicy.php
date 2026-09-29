<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Http;

final class CapturePolicy
{
    /** @var array<int> */
    public $statuses;

    /** @var bool */
    public $trackAll;

    /** @var array<string> */
    public $headers;

    /** @var array<string, array<string>> */
    public $queryByRoute;

    /** @var array<string, array<string>> */
    public $bodyByRoute;

    /** @var array<string> */
    public $trustedProxies;

    /** @var int */
    public $maxBodyBytes;

    /** @var int */
    public $maxJsonDepth;

    /** @var bool */
    public $securityCapture;

    public function __construct(
        array $statuses = array(400, 401, 403, 404, 429, 500, 502, 503),
        bool $trackAll = false,
        array $headers = array(),
        array $queryByRoute = array(),
        array $bodyByRoute = array(),
        array $trustedProxies = array(),
        int $maxBodyBytes = FieldPolicy::DEFAULT_MAX_BODY_BYTES,
        int $maxJsonDepth = FieldPolicy::DEFAULT_MAX_JSON_DEPTH,
        bool $securityCapture = false
    ) {
        $this->statuses = $statuses;
        $this->trackAll = $trackAll;
        $this->headers = $headers;
        $this->queryByRoute = $queryByRoute;
        $this->bodyByRoute = $bodyByRoute;
        $this->trustedProxies = $trustedProxies;
        $this->maxBodyBytes = $maxBodyBytes;
        $this->maxJsonDepth = $maxJsonDepth;
        $this->securityCapture = $securityCapture;
    }

    public function tracks(int $status): bool
    {
        return $this->securityCapture
            || $this->trackAll
            || in_array($status, $this->statuses, true);
    }
}
