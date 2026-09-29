<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Runtime
    |--------------------------------------------------------------------------
    |
    | The Runtime captures and locally spools security telemetry only.
    | It never sends network requests and does not require the LoGuard API key.
    | Delivery credentials belong to the background worker.
    |
    */

    'enabled' => (bool) env('LOGUARD_RUNTIME_ENABLED', true),

    'env' => env(
        'LOGUARD_ENV',
        env('APP_ENV', 'production')
    ),

    'service' => env(
        'LOGUARD_SERVICE',
        env('OTEL_SERVICE_NAME', env('APP_NAME'))
    ),

    'max_event_bytes' => (int) env(
        'LOGUARD_MAX_EVENT_BYTES',
        64 * 1024
    ),

    /*
    |--------------------------------------------------------------------------
    | Local spool
    |--------------------------------------------------------------------------
    */

    'spool_path' => env(
        'LOGUARD_SPOOL_PATH',
        storage_path('loguard-spool')
    ),

    'spool_max_files' => (int) env(
        'LOGUARD_SPOOL_MAX_FILES',
        10000
    ),

    /*
    |--------------------------------------------------------------------------
    | HTTP security capture
    |--------------------------------------------------------------------------
    */

    'middleware' => [
        'security_capture' => (bool) env(
            'LOGUARD_SECURITY_CAPTURE',
            true
        ),

        'track_statuses' => [
            400,
            401,
            403,
            404,
            429,
            500,
            502,
            503,
        ],

        'track_all_requests' => (bool) env(
            'LOGUARD_TRACK_ALL_REQUESTS',
            false
        ),

        // Empty by default. Sensitive credential headers are denied in code.
        'track_headers' => [],

        'max_body_bytes' => (int) env(
            'LOGUARD_MAX_BODY_BYTES',
            32 * 1024
        ),

        'max_body_json_depth' => (int) env(
            'LOGUARD_MAX_BODY_JSON_DEPTH',
            8
        ),

        // Only trust X-Forwarded-For when the direct peer matches this list.
        'trusted_proxies' => array_values(
            array_filter(
                array_map(
                    'trim',
                    explode(
                        ',',
                        (string) env(
                            'LOGUARD_TRUSTED_PROXIES',
                            ''
                        )
                    )
                )
            )
        ),

        // Optional callable(Request): string|null.
        'resolve_user_id' => null,
    ],
];
