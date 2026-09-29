<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Http;

final class RequestContext
{
    /** @var string */
    public $method;

    /** @var string */
    public $path;

    /** @var int */
    public $statusCode;

    /** @var string */
    public $directPeerIp;

    /** @var string|null */
    public $forwardedFor;

    /** @var string|null */
    public $routeName;

    /** @var string|null */
    public $userId;

    /** @var array<string, mixed> */
    public $headers;

    /** @var array<string, mixed> */
    public $query;

    /** @var string|null */
    public $rawBody;

    /** @var string|null */
    public $contentType;

    public function __construct(
        string $method,
        string $path,
        int $statusCode,
        string $directPeerIp,
        ?string $forwardedFor = null,
        ?string $routeName = null,
        ?string $userId = null,
        array $headers = array(),
        array $query = array(),
        ?string $rawBody = null,
        ?string $contentType = null
    ) {
        $this->method = $method;
        $this->path = $path;
        $this->statusCode = $statusCode;
        $this->directPeerIp = $directPeerIp;
        $this->forwardedFor = $forwardedFor;
        $this->routeName = $routeName;
        $this->userId = $userId;
        $this->headers = $headers;
        $this->query = $query;
        $this->rawBody = $rawBody;
        $this->contentType = $contentType;
    }
}
