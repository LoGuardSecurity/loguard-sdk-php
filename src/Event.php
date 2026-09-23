<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

/** A single security event sent to POST /v1/ingest. */
final class Event implements \JsonSerializable
{
    public string $type;
    public string $ip;
    public string $path;
    public int $statusCode;
    public string $ts;
    public ?string $userId;
    public ?string $service;
    /** @var array<string, mixed> */
    public array $meta;

    /**
     * @param array<string, mixed> $meta
     */
    public function __construct(
        string $type,
        string $ip,
        string $path,
        int $statusCode,
        string $ts,
        ?string $userId = null,
        ?string $service = null,
        array $meta = []
    ) {
        $this->type = $type;
        $this->ip = $ip;
        $this->path = $path;
        $this->statusCode = $statusCode;
        $this->ts = $ts;
        $this->userId = $userId;
        $this->service = $service;
        $this->meta = $meta;
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'type' => $this->type,
            'ip' => $this->ip,
            'path' => $this->path,
            'status_code' => $this->statusCode,
            'ts' => $this->ts,
            'user_id' => $this->userId,
            'service' => $this->service,
            'meta' => (object) $this->meta,
        ];
    }
}
