<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LoGuard\Sdk\Client;
use LoGuard\Sdk\Http\CapturePolicy;
use LoGuard\Sdk\Http\FieldPolicy;
use LoGuard\Sdk\Http\HttpEventFactory;
use LoGuard\Sdk\Http\RequestContext;
use LoGuard\Sdk\Laravel\Jobs\SendLoGuardEvents;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class LoGuardMiddleware
{
    public function __construct(
        private readonly Client $client,
        private readonly HttpEventFactory $events = new HttpEventFactory()
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        if (!config('loguard.enabled', false)) {
            return;
        }

        try {
            $settings = (array) config('loguard.middleware', []);
            $query = $request->query();
            $queryParams = is_array($query) ? $query : [];

            $context = new RequestContext(
                $request->method(),
                $request->path(),
                $response->getStatusCode(),
                (string) $request->server->get('REMOTE_ADDR', ''),
                $request->headers->get('X-Forwarded-For'),
                $request->route()->getName(),
                $this->resolveUserId($request),
                $request->headers->all(),
                $queryParams,
                $request->getContent() ?: null,
                $request->headers->get('Content-Type')
            );
            $policy = new CapturePolicy(
                (array) ($settings['track_statuses'] ?? [400, 401, 403, 404, 429, 500, 502, 503]),
                (bool) ($settings['track_all_requests'] ?? false),
                (array) ($settings['track_headers'] ?? []),
                (array) ($settings['track_query_params'] ?? []),
                (array) ($settings['track_body_json_paths'] ?? []),
                (array) ($settings['trusted_proxies'] ?? []),
                (int) ($settings['max_body_bytes'] ?? FieldPolicy::DEFAULT_MAX_BODY_BYTES),
                (int) ($settings['max_body_json_depth'] ?? FieldPolicy::DEFAULT_MAX_JSON_DEPTH)
            );
            $event = $this->events->create($context, $policy);
            if ($event === null) {
                return;
            }

            if (config('loguard.queue_events', false)) {
                SendLoGuardEvents::dispatch([$event])
                    ->onConnection(config('loguard.queue_connection'))
                    ->onQueue(config('loguard.queue_name', 'default'));
                return;
            }

            $this->client->eventAsync(
                (string) $event['type'],
                (string) $event['ip'],
                (string) $event['path'],
                (int) $event['status_code'],
                isset($event['user_id']) ? (string) $event['user_id'] : null,
                null,
                (array) $event['meta']
            );
            $this->client->flush();
        } catch (Throwable $e) {
            report($e);
        }
    }

    private function resolveUserId(Request $request): ?string
    {
        $resolver = config('loguard.middleware.resolve_user_id');
        if (is_callable($resolver)) {
            try {
                $id = $resolver($request);
                return $id !== null ? (string) $id : null;
            } catch (Throwable) {
                return null;
            }
        }

        $user = Auth::user();
        $id = $user?->getAuthIdentifier();

        return $id !== null ? (string) $id : null;
    }
}
