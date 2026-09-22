<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LoGuard\Sdk\Client;
use LoGuard\Sdk\Exceptions\LoGuardException;
use LoGuard\Sdk\Http\ClientIp;
use LoGuard\Sdk\Http\FieldPolicy;
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

        // [NEW — audit remediation] track_all_requests is an explicit,
        // separate opt-in (default: false). Existing installs that only
        // set track_statuses keep exactly the same event volume as
        // before — this flag must be turned on deliberately, never
        // inferred, so nobody's ingest volume/billing changes on an SDK
        // upgrade alone.
        $trackAllRequests = (bool) config('loguard.middleware.track_all_requests', false);
        $trackStatuses = (array) config('loguard.middleware.track_statuses', [400, 401, 403, 404, 429, 500, 502, 503]);
        if (!$trackAllRequests && !in_array($response->getStatusCode(), $trackStatuses, true)) {
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

            // [NEW — audit remediation, Этап 3] Query/body capture: off by
            // default (empty config = FieldPolicy returns nothing), opt-in
            // per named route. Route *name* (not raw path) is the allowlist
            // key so a dynamic segment (e.g. /users/{id}) doesn't require
            // one allowlist entry per id. A request whose route has no
            // name can't be targeted by this allowlist at all — this is a
            // known limitation, not a silent gap: such requests simply
            // never match any configured route key, so nothing is
            // captured for them either way.
            $routeName = $request->route()?->getName();
            if ($routeName !== null) {
                // [FIX — found before shipping] config()'s dot-notation
                // lookup splits on EVERY dot in the key path -- but a
                // Laravel route name is itself dotted (e.g. "auth.login"),
                // so config("...track_query_params.{$routeName}") would
                // have been parsed as nested ['auth']['login'] instead of
                // the single top-level key "auth.login" that
                // 'track_query_params' => ['auth.login' => [...]] actually
                // stores it under -- silently always returning the
                // default. Fetch the whole map once and index into it
                // directly instead of building a dotted string.
                $allQueryAllowlists = (array) config('loguard.middleware.track_query_params', []);
                $allowedQueryParams = (array) ($allQueryAllowlists[$routeName] ?? []);
                $queryCapture = FieldPolicy::captureQuery($allowedQueryParams, $request->query());
                if ($queryCapture !== []) {
                    $meta['query'] = $queryCapture;
                }

                $allBodyAllowlists = (array) config('loguard.middleware.track_body_json_paths', []);
                $allowedBodyPaths = (array) ($allBodyAllowlists[$routeName] ?? []);
                if ($allowedBodyPaths !== []) {
                    $bodyCapture = FieldPolicy::captureBody(
                        $allowedBodyPaths,
                        $request->getContent() ?: null,
                        $request->headers->get('Content-Type'),
                        (int) config('loguard.middleware.max_body_bytes', FieldPolicy::DEFAULT_MAX_BODY_BYTES),
                        (int) config('loguard.middleware.max_body_json_depth', FieldPolicy::DEFAULT_MAX_JSON_DEPTH),
                    );
                    $meta = [...$meta, ...$bodyCapture->toMeta()];
                }
            }

            // [FIX — audit remediation] A plain HTTP 401 is NOT proof of a
            // failed login attempt: it also covers an expired API token on
            // an already-authenticated user, a misconfigured client, a
            // health-check probe against a protected route, etc. The
            // middleware only sees the response status code — it has no
            // way to know why the app returned 401, so it can no longer
            // guess "login_failed" from that alone. Every tracked status,
            // 401 included, is now reported as the same generic
            // 'http_error' event. A real, confirmed failed-login signal is
            // available via Client::recordLoginFailure()/event(type:
            // 'login_failed', ...), called explicitly from the
            // application's own authentication code, where "this was
            // actually a login attempt" is genuinely known. That is a
            // second, independent signal, not a replacement for this one —
            // calling both for the same request is not double-counting,
            // it's two different claims (raw HTTP telemetry vs. a
            // confirmed business event).
            $eventType = 'http_error';

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
