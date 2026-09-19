<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use LoGuard\Sdk\Exceptions\LoGuardException;
use LoGuard\Sdk\Exceptions\LoGuardNotInitializedException;
use LoGuard\Sdk\Exceptions\LoGuardValidationException;

/**
 * Core LoGuard client.
 *
 * Framework-agnostic: has no knowledge of Laravel or any other
 * framework. The Laravel integration (LoGuard\Sdk\Laravel\...) is a
 * thin adapter built entirely on top of this public API.
 *
 * API shape is the idiomatic-PHP equivalent of the canonical
 * initialize / configure / start / capture / event / flush / shutdown
 * lifecycle shared by the other LoGuard SDKs:
 *
 *   initialize + configure + start  -> new Client($config) / Client::init()
 *   capture / event                 -> event() / eventBatch() / eventAsync()
 *   flush                           -> flush()
 *   shutdown                        -> shutdown()
 */
final class Client
{
    private Config $config;
    private AlertsClient $alerts;

    /** @var Event[] */
    private array $pending = [];
    private int $maxQueueSize = 2000;
    private int $maxBatchSize = 50;
    private bool $shutdownRegistered = false;
    private bool $isShutdown = false;

    /** @var callable|null */
    private $onDropped = null;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->alerts = new AlertsClient($this);
    }

    /**
     * Convenience constructor mirroring monitor.init(...) in the other
     * SDKs. Most PHP apps should instead construct a Client (or, in
     * Laravel, resolve LoGuard\Sdk\Client from the container) and keep
     * a single long-lived instance per request/worker rather than a
     * process-wide singleton, since PHP has no persistent process
     * shared across requests the way Python/Node/Go/Java do.
     *
     * @param array<string, mixed> $options
     */
    public static function init(array $options): self
    {
        return new self(Config::fromArray($options));
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function alerts(): AlertsClient
    {
        return $this->alerts;
    }

    /**
     * Set a callback invoked when a queued (eventAsync) event is
     * dropped because the in-memory buffer is full. Useful for
     * metrics/observability; never lets a full buffer throw.
     *
     * @param callable(Event):void $callback
     */
    public function onDropped(callable $callback): void
    {
        $this->onDropped = $callback;
    }

    /**
     * Track a single security event. Blocking — waits for the LoGuard
     * API response (bounded by config timeout * retries).
     *
     * @param array<string, mixed> $meta
     */
    public function event(
        string $type,
        string $ip,
        string $path,
        int $statusCode,
        ?string $userId = null,
        ?string $service = null,
        array $meta = [],
        ?DateTimeInterface $ts = null
    ): IngestResult {
        $event = $this->buildEvent($type, $ip, $path, $statusCode, $userId, $service, $meta, $ts);

        return $this->sendEventsSync([$event]);
    }

    /**
     * Track multiple events in a single request.
     *
     * @param array<int, array<string, mixed>> $events Each element uses the same
     *        keys as event()'s named parameters: type, ip, path, status_code, ...
     */
    public function eventBatch(array $events): IngestResult
    {
        $built = array_map(fn (array $e) => $this->buildEventFromArray($e), $events);

        return $this->sendEventsSync($built);
    }

    /**
     * Queue an event for later delivery without blocking the caller.
     *
     * PHP has no persistent background worker inside a single request,
     * so "fire and forget" here means: buffer in memory (bounded,
     * oldest-dropped-first once full) and flush automatically when the
     * process shuts down (register_shutdown_function) or when flush()
     * is called explicitly. In Laravel, prefer the queue-backed mode
     * (see LoGuard\Sdk\Laravel — QUEUE_EVENTS config) which dispatches
     * a real background job instead of relying on shutdown timing.
     *
     * Never throws.
     *
     * @param array<string, mixed> $meta
     */
    public function eventAsync(
        string $type,
        string $ip,
        string $path,
        int $statusCode,
        ?string $userId = null,
        ?string $service = null,
        array $meta = [],
        ?DateTimeInterface $ts = null
    ): void {
        try {
            $event = $this->buildEvent($type, $ip, $path, $statusCode, $userId, $service, $meta, $ts);
        } catch (LoGuardException) {
            return;
        }

        if (count($this->pending) >= $this->maxQueueSize) {
            $dropped = array_shift($this->pending);
            if ($this->onDropped !== null && $dropped !== null) {
                ($this->onDropped)($dropped);
            }
        }

        $this->pending[] = $event;
        $this->registerShutdownFlush();
    }

    /**
     * Send everything currently queued by eventAsync(), in batches of
     * at most maxBatchSize. Failures are swallowed (matching the other
     * SDKs' fire-and-forget semantics) — flush() never throws.
     */
    public function flush(): void
    {
        while (!empty($this->pending)) {
            $batch = array_splice($this->pending, 0, $this->maxBatchSize);
            try {
                $this->sendEventsSync($batch);
            } catch (LoGuardException) {
                // Best-effort delivery: drop this batch and keep going,
                // never let a transport failure surface from flush().
                continue;
            }
        }
    }

    /**
     * Flush any queued events and mark the client as shut down.
     * Safe to call multiple times.
     */
    public function shutdown(): void
    {
        if ($this->isShutdown) {
            return;
        }
        $this->isShutdown = true;
        $this->flush();
    }

    private function registerShutdownFlush(): void
    {
        if ($this->shutdownRegistered) {
            return;
        }
        $this->shutdownRegistered = true;
        register_shutdown_function(function (): void {
            $this->flush();
        });
    }

    /**
     * Keys match the wire format exactly (snake_case) — the same shape
     * eventBatch()'s caller writes and Event::jsonSerialize() produces,
     * so a batch built from decoded JSON round-trips without translation.
     *
     * @param array<string, mixed> $e
     */
    private function buildEventFromArray(array $e): Event
    {
        return $this->buildEvent(
            (string) ($e['type'] ?? ''),
            (string) ($e['ip'] ?? ''),
            (string) ($e['path'] ?? ''),
            (int) ($e['status_code'] ?? 0),
            isset($e['user_id']) ? (string) $e['user_id'] : null,
            isset($e['service']) ? (string) $e['service'] : null,
            (array) ($e['meta'] ?? []),
            $e['ts'] ?? null
        );
    }

    /**
     * Validation is intentionally identical to the other SDKs'
     * _build_event()/buildEvent(): required fields, status_code range,
     * path normalization/truncation, lowercasing + length caps on
     * type/ip/service, so a malformed call fails the same way in
     * every language before anything is sent over the wire.
     *
     * @param array<string, mixed> $meta
     */
    private function buildEvent(
        string $type,
        string $ip,
        string $path,
        int $statusCode,
        ?string $userId,
        ?string $service,
        array $meta,
        $ts
    ): Event {
        if (trim($type) === '') {
            throw new LoGuardValidationException('event type is required');
        }
        if (trim($ip) === '') {
            throw new LoGuardValidationException('event ip is required');
        }
        if (trim($path) === '') {
            throw new LoGuardValidationException('event path is required');
        }
        if ($statusCode < 100 || $statusCode > 599) {
            throw new LoGuardValidationException('status_code must be in range 100..599');
        }

        $p = trim($path);
        if (strpos($p, '/') !== 0) {
            $p = '/' . $p;
        }
        if (strlen($p) > 1024) {
            $p = substr($p, 0, 1024);
        }

        $m = $meta;
        $m['env'] = $this->config->env;

        $svc = $service ?? $this->config->service;

        $tsValue = $ts;
        if ($tsValue instanceof DateTimeInterface) {
            $tsString = $tsValue->format(DateTimeInterface::ATOM);
        } elseif (is_string($tsValue) && $tsValue !== '') {
            $tsString = $tsValue;
        } else {
            $tsString = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DateTimeInterface::ATOM);
        }

        return new Event(
            mb_substr(strtolower(trim($type)), 0, 64),
            mb_substr(trim($ip), 0, 64),
            $p,
            $statusCode,
            $tsString,
            $userId !== null ? mb_substr((string) $userId, 0, 128) : null,
            $svc !== null ? mb_substr(strtolower(trim((string) $svc)), 0, 64) : null,
            $m
        );
    }

    /**
     * @param Event[] $events
     */
    private function sendEventsSync(array $events): IngestResult
    {
        $payload = ['events' => array_map(fn (Event $e) => $e->jsonSerialize(), $events)];
        $data = Transport::sendSync(
            $this->config->ingestUrl(),
            $this->config->defaultHeaders(),
            $payload,
            $this->config->timeout,
            $this->config->retries,
            'POST',
            $this->config->apiKey
        );

        return IngestResult::fromResponse($data);
    }
}
