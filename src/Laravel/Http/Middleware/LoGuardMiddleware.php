<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LoGuard\Sdk\Client;
use LoGuard\Sdk\Exceptions\LoGuardException;
use LoGuard\Sdk\Http\ClientIp;
use LoGuard\Sdk\Http\HeaderPolicy;
use LoGuard\Sdk\Laravel\Jobs\SendLoGuardEvents;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Laravel HTTP middleware that automatically reports HTTP errors as
 * LoGuard security events — the Laravel equivalent of
 * loguard/integrations/fastapi.py's LoGuardMiddleware.
 *
 * Usage (bootstrap/app.php, Laravel 11+):
 *
 *   ->withMiddleware(function (Middleware $middleware) {
 *       $middleware->append(\LoGuard\Sdk\Laravel\Http\Middleware\LoGuardMiddleware::class);
 *   })
 *
 * Or (Laravel 10 and earlier, app/Http/Kernel.php):
 *
 *   protected $middleware = [
 *       // ...
 *       \LoGuard\Sdk\Laravel\Http\Middleware\LoGuardMiddleware::class,
 *   ];
 *
 * Design notes:
 *  - Registered via `terminate()`, so event delivery (or queue
 *    dispatch) happens strictly AFTER the response has been sent to
 *    the client on servers that support FastCGI/`fastcgi_finish_request`
 *    (PHP-FPM). This keeps the middleware from adding LoGuard's
 *    network latency to the user-facing request.
 *  - When `loguard.queue_events` is true, the event is handed to a
 *    real Laravel queue job (SendLoGuardEvents) instead of being sent
 *    inline from terminate() — the recommended mode for production
 *    and for queue workers processing jobs (no HTTP request/response
 *    cycle to hook `terminate()` on there at all).
 *  - Every exception from the SDK is caught here: a LoGuard outage or
 *    misconfiguration must never turn into a 500 for your users.
 *  - X-Forwarded-For is resolved via ClientIp (trusted-proxy aware,
 *    secure by default) and headers are collected via HeaderPolicy
 *    (deny-list enforced in code, not just documented).
 */
final class LoGuardMiddleware
{
    private Client $client;

    public function __construct(Client $client)
    {
        $this->client = $client;
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

        $trackStatuses = (array) config('loguard.middleware.track_statuses', [400, 401, 403, 404, 429, 500, 502, 503]);
        if (!in_array($response->getStatusCode(), $trackStatuses, true)) {
            return;
        }

        try {
            $trustedProxies = (array) config('loguard.middleware.trusted_proxies', []);
            $ip = ClientIp::resolve(
                (string) $request->server->get('REMOTE_ADDR', ''),
                $request->headers->get('X-Forwarded-For'),
                $trustedProxies
            );

            $userId = $this->resolveUserId($request);

            $trackHeaders = HeaderPolicy::sanitizeRequested((array) config('loguard.middleware.track_headers', []));
            $collected = HeaderPolicy::collect($trackHeaders, function (string $name) use ($request): ?string {
                return $request->headers->get($name);
            });

            $meta = [];
            if (!empty($collected)) {
                $meta['headers'] = $collected;
            }

            $eventType = $response->getStatusCode() === 401 ? 'login_failed' : 'http_error';

            $payload = [
                'type' => $eventType,
                'ip' => $ip,
                'path' => $request->path() === '/' ? '/' : '/' . ltrim($request->path(), '/'),
                'status_code' => $response->getStatusCode(),
                'user_id' => $userId,
                'meta' => $meta,
            ];

            if (config('loguard.queue_events', false)) {
                SendLoGuardEvents::dispatch([$payload])
                    ->onConnection(config('loguard.queue_connection'))
                    ->onQueue(config('loguard.queue_name', 'default'));

                return;
            }

            $this->client->eventAsync(
                (string) $payload['type'],
                (string) $payload['ip'],
                (string) $payload['path'],
                (int) $payload['status_code'],
                $payload['user_id'],
                null,
                $payload['meta']
            );
            $this->client->flush();
        } catch (LoGuardException $e) {
            report($e);
        } catch (Throwable $e) {
            // Never let an unexpected SDK failure affect the response
            // that has already been sent to the user.
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
            } catch (Throwable $e) {
                return null;
            }
        }

        $user = Auth::user();
        if ($user === null) {
            return null;
        }

        $id = method_exists($user, 'getAuthIdentifier') ? $user->getAuthIdentifier() : null;

        return $id !== null ? (string) $id : null;
    }
}
