<?php

declare(strict_types=1);

/*
 * LoGuard generic PHP runtime bootstrap.
 *
 * Designed for PHP-FPM auto_prepend_file integration.
 * Customer application source code does not need to be modified.
 *
 * Request-path guarantees:
 * - fail open;
 * - no synchronous network delivery;
 * - sensitive values are filtered before spool persistence;
 * - bounded request-body capture;
 * - no multipart/file/binary capture.
 */

if (PHP_SAPI === 'cli') {
    return;
}

if (defined('LOGUARD_RUNTIME_BOOTSTRAPPED')) {
    return;
}

define('LOGUARD_RUNTIME_BOOTSTRAPPED', true);

(function (): void {
    try {
        require_once __DIR__ . '/autoload.php';

        $configPath = getenv('LOGUARD_RUNTIME_CONFIG');

        if ($configPath === false || trim($configPath) === '') {
            $configPath = '/etc/loguard/php-runtime.env';
        }

        $settings = [];

        if (is_file($configPath) && is_readable($configPath)) {
            $parsed = parse_ini_file(
                $configPath,
                false,
                INI_SCANNER_RAW
            );

            if (is_array($parsed)) {
                $settings = $parsed;
            }
        }

        $value = static function (
            string $name,
            mixed $default = null
        ) use ($settings): mixed {
            $env = getenv($name);

            if ($env !== false && $env !== '') {
                return $env;
            }

            return $settings[$name] ?? $default;
        };

        $apiKey = trim((string) $value('LOGUARD_API_KEY', ''));

        /*
         * Missing configuration must never affect the customer app.
         */
        if ($apiKey === '') {
            return;
        }

        $spoolPath = trim(
            (string) $value(
                'LOGUARD_SPOOL_PATH',
                '/var/lib/loguard/spool'
            )
        );

        if ($spoolPath === '') {
            return;
        }

        $config = \LoGuard\Sdk\Config::fromArray([
            'api_key' => $apiKey,
            'base_url' => (string) $value(
                'LOGUARD_BASE_URL',
                \LoGuard\Sdk\Config::DEFAULT_BASE_URL
            ),
            'env' => (string) $value(
                'LOGUARD_ENV',
                'production'
            ),
            'service' => $value(
                'LOGUARD_SERVICE',
                null
            ),
            'timeout' => (float) $value(
                'LOGUARD_TIMEOUT',
                \LoGuard\Sdk\Config::DEFAULT_TIMEOUT
            ),
            'retries' => (int) $value(
                'LOGUARD_RETRIES',
                \LoGuard\Sdk\Config::DEFAULT_RETRIES
            ),
            'max_event_bytes' => (int) $value(
                'LOGUARD_MAX_EVENT_BYTES',
                \LoGuard\Sdk\Config::DEFAULT_MAX_EVENT_BYTES
            ),
            'allow_insecure_transport' => filter_var(
                (string) $value(
                    'LOGUARD_ALLOW_INSECURE_TRANSPORT',
                    'false'
                ),
                FILTER_VALIDATE_BOOLEAN
            ),
        ]);

        /*
         * FileSpool is the important part here:
         * Client::eventAsync() writes locally instead of talking to
         * the LoGuard API from the application request.
         */
        $client = new \LoGuard\Sdk\Client(
            $config,
            null,
            null,
            new \LoGuard\Sdk\Dispatch\FileSpool($spoolPath)
        );

        /*
         * Security capture intentionally tracks successful responses too.
         */
        $policy = new \LoGuard\Sdk\Http\CapturePolicy(
            securityCapture: true
        );

        $events = new \LoGuard\Sdk\Http\HttpEventFactory();

        $method = (string) ($_SERVER['REQUEST_METHOD'] ?? '');
        $requestUri = (string) ($_SERVER['REQUEST_URI'] ?? '/');

        $path = parse_url($requestUri, PHP_URL_PATH);

        if (!is_string($path) || $path === '') {
            $path = '/';
        }

        $directPeerIp = trim(
            (string) ($_SERVER['REMOTE_ADDR'] ?? '')
        );

        if ($method === '' || $directPeerIp === '') {
            return;
        }

        /*
         * Capture request values before the framework/application has a
         * chance to mutate superglobals.
         */
        $query = is_array($_GET) ? $_GET : [];

        $contentType = isset($_SERVER['CONTENT_TYPE'])
            ? (string) $_SERVER['CONTENT_TYPE']
            : null;

        $forwardedFor = isset($_SERVER['HTTP_X_FORWARDED_FOR'])
            ? (string) $_SERVER['HTTP_X_FORWARDED_FOR']
            : null;

        /*
         * Do not even read php://input for multipart, files or arbitrary
         * binary formats. Read at most maxBodyBytes + 1 so oversized input
         * can be detected without loading the entire request into memory.
         */
        $rawBody = null;

        $normalizedContentType = strtolower(
            trim((string) preg_replace(
                '/\s*;.*$/',
                '',
                (string) $contentType
            ))
        );

        $bodyIsAllowed =
            $normalizedContentType === 'application/json'
            || $normalizedContentType ===
                'application/x-www-form-urlencoded'
            || (
                str_starts_with(
                    $normalizedContentType,
                    'application/'
                )
                && str_ends_with(
                    $normalizedContentType,
                    '+json'
                )
            );

        if ($bodyIsAllowed) {
            $body = file_get_contents(
                'php://input',
                false,
                null,
                0,
                $policy->maxBodyBytes + 1
            );

            if (is_string($body)) {
                $rawBody = $body;
            }
        }

        $startedAt = hrtime(true);

        register_shutdown_function(
            static function () use (
                $client,
                $policy,
                $events,
                $method,
                $path,
                $directPeerIp,
                $forwardedFor,
                $query,
                $rawBody,
                $contentType,
                $startedAt
            ): void {
                try {
                    $status = http_response_code();

                    if (!is_int($status) || $status < 100 || $status > 599) {
                        $status = 200;
                    }

                    /*
                     * If PHP terminated with a fatal error before setting an
                     * HTTP error status, represent it as 500 in telemetry
                     * without changing the application's actual response.
                     */
                    $lastError = error_get_last();

                    if (
                        is_array($lastError)
                        && in_array(
                            $lastError['type'] ?? null,
                            [
                                E_ERROR,
                                E_PARSE,
                                E_CORE_ERROR,
                                E_COMPILE_ERROR,
                                E_USER_ERROR,
                            ],
                            true
                        )
                        && $status < 500
                    ) {
                        $status = 500;
                    }

                    $event = $events->create(
                        new \LoGuard\Sdk\Http\RequestContext(
                            $method,
                            $path,
                            $status,
                            $directPeerIp,
                            $forwardedFor,
                            null,
                            null,
                            [],
                            $query,
                            $rawBody,
                            $contentType
                        ),
                        $policy
                    );

                    if ($event === null) {
                        return;
                    }

                    $meta = (array) $event['meta'];

                    $elapsedNs = hrtime(true) - $startedAt;

                    if ($elapsedNs >= 0) {
                        $meta['duration_ms'] = round(
                            $elapsedNs / 1_000_000,
                            3
                        );
                    }

                    $client->eventAsync(
                        (string) $event['type'],
                        (string) $event['ip'],
                        (string) $event['path'],
                        (int) $event['status_code'],
                        null,
                        null,
                        $meta
                    );
                } catch (\Throwable) {
                    /*
                     * Monitoring must never become an application
                     * availability dependency.
                     */
                }
            }
        );
    } catch (\Throwable) {
        /*
         * Fail open during bootstrap as well.
         */
    }
})();
