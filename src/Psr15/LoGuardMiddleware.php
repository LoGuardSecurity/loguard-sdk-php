<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Psr15;

use LoGuard\Sdk\Client;
use LoGuard\Sdk\Http\CapturePolicy;
use LoGuard\Sdk\Http\HttpEventFactory;
use LoGuard\Sdk\Http\RequestContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class LoGuardMiddleware implements MiddlewareInterface
{
    /** @param callable(ServerRequestInterface):?string|null $userId */
    public function __construct(
        private readonly Client $client,
        private readonly CapturePolicy $policy = new CapturePolicy(),
        private readonly HttpEventFactory $events = new HttpEventFactory(),
        private readonly mixed $userId = null
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        try {
            $server = $request->getServerParams();
            $userId = is_callable($this->userId) ? ($this->userId)($request) : null;
            $event = $this->events->create(new RequestContext(
                $request->getMethod(),
                $request->getUri()->getPath(),
                $response->getStatusCode(),
                (string) ($server['REMOTE_ADDR'] ?? ''),
                $request->getHeaderLine('X-Forwarded-For') ?: null,
                is_string($request->getAttribute('route.name')) ? $request->getAttribute('route.name') : null,
                $userId,
                $request->getHeaders(),
                $request->getQueryParams(),
                (string) $request->getBody(),
                $request->getHeaderLine('Content-Type') ?: null
            ), $this->policy);

            if ($event !== null) {
                $this->client->eventAsync(
                    (string) $event['type'],
                    (string) $event['ip'],
                    (string) $event['path'],
                    (int) $event['status_code'],
                    isset($event['user_id']) ? (string) $event['user_id'] : null,
                    null,
                    (array) $event['meta']
                );
            }
        } catch (\Throwable) {
            // Telemetry must never change the application response.
        }

        return $response;
    }
}
