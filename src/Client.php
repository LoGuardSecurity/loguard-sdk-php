<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use LoGuard\Sdk\Exceptions\LoGuardValidationException;
use LoGuard\Sdk\Contracts\TransportInterface;
use LoGuard\Sdk\Contracts\EventSinkInterface;
use LoGuard\Sdk\Privacy\Sanitizer;
use LoGuard\Sdk\Transport\CurlTransport;
use Throwable;

/**
 * Core LoGuard client.
 *
 * Framework-agnostic: has no knowledge of Laravel or any other
 * framework. The Laravel integration (LoGuard\Sdk\Laravel\...) is a
 * thin adapter built entirely on top of this public API.
 *
 * The core has no framework dependency. Framework adapters build events
 * through this public API and may supply their own transport or queue.
 */
final class Client
{
    private Config $config;
    private TransportInterface $transport;
    private Sanitizer $sanitizer;
    private ?EventSinkInterface $eventSink;

    /** @var Event[] */
    private array $pending = [];
    private int $maxQueueSize = 2000;
    private int $maxBatchSize = 50;
    private bool $shutdownRegistered = false;
    private bool $isShutdown = false;

    /** @var callable|null */
    private $onDropped = null;

    public function __construct(
        Config $config,
        ?TransportInterface $transport = null,
        ?Sanitizer $sanitizer = null,
        ?EventSinkInterface $eventSink = null
    )
    {
        $this->config = $config;
        $this->transport = $transport ?? new CurlTransport();
        $this->sanitizer = $sanitizer ?? new Sanitizer();
        $this->eventSink = $eventSink;
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
     * Convenience wrapper around eventAsync() for a CONFIRMED failed login
     * attempt. This is the explicit, opt-in counterpart to removing the
     * automatic "any HTTP 401 -> login_failed" inference that used to live
     * in LoGuardMiddleware — call this from your own authentication code
     * (where "this really was a login attempt, and it really failed" is
     * actually known), never from generic HTTP-error handling.
     *
     * Fire-and-forget, matching eventAsync() -- never throws.
     *
     * @param array<string, mixed> $meta
     */
    public function recordLoginFailure(
        string $ip,
        string $path = '/login',
        ?string $userId = null,
        array $meta = []
    ): void {
        $this->eventAsync('login_failed', $ip, $path, 401, $userId, null, $meta);
    }

    /**
     * Track multiple events in a single request.
     *
     * @param array<int, array<string, mixed>> $events Each element uses the same
     *        keys as event()'s named parameters: type, ip, path, status_code, ...
     */
    public function eventBatch(array $events, ?int $attempts = null): IngestResult
    {
        if (count($events) > $this->maxBatchSize) {
            throw new LoGuardValidationException("a batch may contain at most {$this->maxBatchSize} events");
        }
        if ($attempts !== null && ($attempts < 1 || $attempts > 5)) {
            throw new LoGuardValidationException('attempts must be between 1 and 5');
        }
        $built = array_map(fn (array $e) => $this->buildEventFromArray($e), $events);

        return $this->sendEventsSync($built, $attempts);
    }

    /**
     * Queue an event for later delivery without blocking the caller.
     *
     * With an EventSinkInterface this writes to the configured queue or
     * spool. Without one it uses the bounded compatibility buffer and
     * flushes during process shutdown.
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
        } catch (Throwable) {
            return;
        }

        if ($this->eventSink !== null) {
            try {
                $queued = $this->eventSink->enqueue($event);
            } catch (Throwable) {
                $queued = false;
            }
            if (!$queued) {
                $this->notifyDropped($event);
            }
            return;
        }

        if (count($this->pending) >= $this->maxQueueSize) {
            $dropped = array_shift($this->pending);
            if ($dropped !== null) {
                $this->notifyDropped($dropped);
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
            } catch (Throwable) {
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

    private function notifyDropped(Event $event): void
    {
        if ($this->onDropped === null) {
            return;
        }
        try {
            ($this->onDropped)($event);
        } catch (Throwable) {
            // Observability callbacks are isolated from application code.
        }
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
        DateTimeInterface|string|null $ts
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

        $m = $this->sanitizer->meta($meta);
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

        $event = new Event(
            mb_substr(strtolower(trim($type)), 0, 64),
            mb_substr(trim($ip), 0, 64),
            $p,
            $statusCode,
            $tsString,
            $userId !== null ? mb_substr((string) $userId, 0, 128) : null,
            $svc !== null ? mb_substr(strtolower(trim((string) $svc)), 0, 64) : null,
            $m
        );

        try {
            $encoded = Signing::buildBody($event->jsonSerialize());
        } catch (\JsonException $e) {
            throw new LoGuardValidationException('event contains invalid UTF-8 or non-JSON data', 0, $e);
        }
        if (strlen($encoded) > $this->config->maxEventBytes) {
            throw new LoGuardValidationException('event exceeds max_event_bytes');
        }

        return $event;
    }

    /**
     * @param Event[] $events
     */
    private function sendEventsSync(array $events, ?int $attempts = null): IngestResult
    {
        $payload = ['events' => array_map(fn (Event $e) => $e->jsonSerialize(), $events)];
        $data = $this->transport->send(
            $this->config->ingestUrl(),
            $this->config->defaultHeaders(),
            $payload,
            $this->config->timeout,
            $attempts ?? $this->config->retries,
            'POST',
            $this->config->apiKey
        );

        return IngestResult::fromResponse($data);
    }
}
