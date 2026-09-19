<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | API key
    |--------------------------------------------------------------------------
    |
    | Your LoGuard API key from the dashboard. Never commit this — keep it
    | in .env only. Leave LOGUARD_API_KEY unset to disable the SDK entirely
    | (see "enabled" below).
    |
    */
    'api_key' => env('LOGUARD_API_KEY'),

    /*
    |--------------------------------------------------------------------------
    | Enabled
    |--------------------------------------------------------------------------
    |
    | Defaults to "is an api_key configured?". Set LOGUARD_ENABLED=false to
    | force-disable (e.g. in local/testing environments) even if a key is
    | present. When disabled, the middleware and facade become no-ops
    | instead of raising LoGuardNotInitializedException, so you don't need
    | to guard every call site.
    |
    */
    'enabled' => env('LOGUARD_ENABLED', env('LOGUARD_API_KEY') !== null),

    'base_url' => env('LOGUARD_BASE_URL', 'https://loguard.org'),

    'env' => env('LOGUARD_ENV', env('APP_ENV', 'production')),

    'service' => env('LOGUARD_SERVICE', env('OTEL_SERVICE_NAME', env('APP_NAME'))),

    'timeout' => (float) env('LOGUARD_TIMEOUT', 10.0),

    'retries' => (int) env('LOGUARD_RETRIES', 3),

    /*
    |--------------------------------------------------------------------------
    | Allow insecure transport
    |--------------------------------------------------------------------------
    |
    | Off by default -- base_url must be https://. Only set this for a
    | trusted local proxy during development; never in production, since
    | your API key and request signatures would travel in plaintext.
    |
    */
    'allow_insecure_transport' => (bool) env('LOGUARD_ALLOW_INSECURE_TRANSPORT', false),

    /*
    |--------------------------------------------------------------------------
    | Middleware
    |--------------------------------------------------------------------------
    */
    'middleware' => [

        // HTTP status codes that get reported as LoGuard events.
        'track_statuses' => [400, 401, 403, 404, 429, 500, 502, 503],

        // Header names to forward to LoGuard's exploit-pattern detectors.
        // Empty by default -- nothing is collected unless you opt in.
        // A fixed deny-list (Authorization, Cookie, Set-Cookie, X-Api-Key,
        // X-Auth-Token, Proxy-Authorization) is enforced in code and can
        // never be overridden here, regardless of what you list.
        'track_headers' => [],

        // IPs/CIDRs of proxies YOU control (e.g. your load balancer).
        // X-Forwarded-For is only trusted when the direct TCP peer is in
        // this list -- secure by default, empty means never trust it.
        'trusted_proxies' => array_filter(explode(',', (string) env('LOGUARD_TRUSTED_PROXIES', ''))),

        // Resolve the authenticated user id to attach to events. Uses
        // Laravel's default auth guard by default.
        'resolve_user_id' => null, // callable(\Illuminate\Http\Request): ?string, set in a service provider if needed.
    ],

    /*
    |--------------------------------------------------------------------------
    | Queue-backed delivery
    |--------------------------------------------------------------------------
    |
    | When true, events captured via the middleware/facade's queued API
    | are dispatched as a real Laravel queue job (LoGuard\Sdk\Laravel\Jobs\
    | SendLoGuardEvents) instead of being flushed at request end. This is
    | the recommended mode for production: delivery survives worker
    | restarts and never adds latency to the HTTP response, at the cost of
    | needing a configured queue worker.
    |
    */
    'queue_events' => (bool) env('LOGUARD_QUEUE_EVENTS', false),
    'queue_connection' => env('LOGUARD_QUEUE_CONNECTION'),
    'queue_name' => env('LOGUARD_QUEUE_NAME', 'default'),
];
