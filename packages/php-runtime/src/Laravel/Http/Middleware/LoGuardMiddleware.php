<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use LoGuard\Runtime\Dispatch\FileSpool;
use LoGuard\Runtime\EventBuilder;
use LoGuard\Runtime\Http\CapturePolicy;
use LoGuard\Runtime\Http\FieldPolicy;
use LoGuard\Runtime\Http\HttpEventFactory;
use LoGuard\Runtime\Http\RequestContext;
use Symfony\Component\HttpFoundation\Response;

final class LoGuardMiddleware
{
    /** @var HttpEventFactory */
    private $events;

    /** @var EventBuilder */
    private $builder;

    /** @var FileSpool */
    private $spool;

    public function __construct(
        HttpEventFactory $events,
        EventBuilder $builder,
        FileSpool $spool
    ) {
        $this->events = $events;
        $this->builder = $builder;
        $this->spool = $spool;
    }

    public function handle(
        Request $request,
        Closure $next
    ): Response {
        return $next($request);
    }

    public function terminate(
        Request $request,
        Response $response
    ): void {
        if (!(bool) config(
            'loguard-runtime.enabled',
            true
        )) {
            return;
        }

        try {
            $settings = (array) config(
                'loguard-runtime.middleware',
                array()
            );

            $route = $request->route();
            $routeName = null;

            if (
                is_object($route)
                && method_exists($route, 'getName')
            ) {
                $name = $route->getName();

                if ($name !== null) {
                    $routeName = (string) $name;
                }
            }

            $queryParams = $request->query->all();

            if (!is_array($queryParams)) {
                $queryParams = array();
            }

            $context = new RequestContext(
                $request->method(),
                $request->path(),
                $response->getStatusCode(),
                (string) $request->server->get(
                    'REMOTE_ADDR',
                    ''
                ),
                $request->headers->get(
                    'X-Forwarded-For'
                ),
                $routeName,
                $this->resolveUserId(
                    $request,
                    $settings
                ),
                $request->headers->all(),
                $queryParams,
                $request->getContent() ?: null,
                $request->headers->get(
                    'Content-Type'
                )
            );

            $policy = new CapturePolicy(
                isset($settings['track_statuses'])
                    && is_array($settings['track_statuses'])
                    ? $settings['track_statuses']
                    : array(
                        400,
                        401,
                        403,
                        404,
                        429,
                        500,
                        502,
                        503,
                    ),
                isset($settings['track_all_requests'])
                    ? (bool) $settings['track_all_requests']
                    : false,
                isset($settings['track_headers'])
                    && is_array($settings['track_headers'])
                    ? $settings['track_headers']
                    : array(),
                array(),
                array(),
                isset($settings['trusted_proxies'])
                    && is_array($settings['trusted_proxies'])
                    ? $settings['trusted_proxies']
                    : array(),
                isset($settings['max_body_bytes'])
                    ? (int) $settings['max_body_bytes']
                    : FieldPolicy::DEFAULT_MAX_BODY_BYTES,
                isset($settings['max_body_json_depth'])
                    ? (int) $settings['max_body_json_depth']
                    : FieldPolicy::DEFAULT_MAX_JSON_DEPTH,
                array_key_exists(
                    'security_capture',
                    $settings
                )
                    ? (bool) $settings['security_capture']
                    : true
            );

            $event = $this->events->create(
                $context,
                $policy
            );

            if ($event === null) {
                return;
            }

            $event = $this->builder->build($event);

            if ($event === null) {
                return;
            }

            // Best-effort and fail-open. No network I/O occurs here.
            $this->spool->enqueue($event);
        } catch (\Throwable $e) {
            // Security telemetry must never affect the application response.
            try {
                if (function_exists('report')) {
                    report($e);
                }
            } catch (\Throwable $ignored) {
                // Reporting failures are isolated too.
            }
        }
    }

    /**
     * @param array<string, mixed> $settings
     */
    private function resolveUserId(
        Request $request,
        array $settings
    ): ?string {
        $resolver = isset(
            $settings['resolve_user_id']
        )
            ? $settings['resolve_user_id']
            : null;

        if (is_callable($resolver)) {
            try {
                $id = call_user_func(
                    $resolver,
                    $request
                );

                return $id !== null
                    ? (string) $id
                    : null;
            } catch (\Throwable $e) {
                return null;
            }
        }

        try {
            $user = $request->user();

            if (
                is_object($user)
                && method_exists(
                    $user,
                    'getAuthIdentifier'
                )
            ) {
                $id = $user->getAuthIdentifier();

                return $id !== null
                    ? (string) $id
                    : null;
            }
        } catch (\Throwable $e) {
            return null;
        }

        return null;
    }
}
