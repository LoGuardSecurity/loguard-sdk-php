# LoGuard PHP Runtime

LoGuard PHP Runtime connects PHP applications to the LoGuard Security Intelligence Platform.

It collects security-relevant HTTP telemetry inside the application, removes sensitive fields locally, writes events to a local spool, and sends them to LoGuard from a background worker.

The request path does not make network calls to LoGuard.

## Requirements

- PHP 7.4 or later
- Composer
- ext-json
- ext-curl

Laravel is supported through Composer package discovery.

## Installation

```bash
composer require loguard/php-runtime:^0.1
```

For Laravel applications, the service provider and LoGuard HTTP middleware are registered automatically.

No manual change to `app/Http/Kernel.php` is required when package discovery is enabled.

## Configure LoGuard

Add your project API key and service name to the application environment:

```env
LOGUARD_API_KEY=your_project_api_key
LOGUARD_SERVICE=my-application
```

The API key is used by the background delivery worker.

The Laravel request middleware does not use the API key and does not send requests to LoGuard directly.

## Run the worker

From the Laravel application root:

```bash
php vendor/bin/loguard-runtime-worker
```

In a Laravel application, the worker automatically uses:

```text
storage/loguard-spool
```

The worker also loads the application's `.env` when Laravel's `vlucas/phpdotenv` dependency is available.

For production, run the worker periodically or through your process manager.

Example cron entry:

```cron
* * * * * cd /path/to/application && php vendor/bin/loguard-runtime-worker >/dev/null 2>&1
```

## How it works

The default Laravel flow is:

```text
HTTP request
    |
LoGuard middleware
    |
local filtering and normalization
    |
storage/loguard-spool
    |
LoGuard Runtime worker
    |
LoGuard ingest
    |
security detection
```

Application requests stay independent from LoGuard availability.

If telemetry processing fails, the application request continues normally.

## HTTP security capture

Security capture is enabled by default.

The Runtime can collect bounded context from:

- request path
- query parameters
- JSON request bodies
- vendor JSON content types
- form-urlencoded request bodies
- HTTP response status
- client IP
- authenticated Laravel user identifier
- explicitly selected safe headers

Security capture is not limited to error responses.

Requests returning `200`, `302`, or another successful status may still contain security-relevant activity.

## Sensitive data

Sensitive fields are removed before an event is written to disk.

The Runtime rejects common credential and private-data field names including:

- passwords
- access and refresh tokens
- API keys
- authorization values
- cookies
- sessions
- private keys
- client secrets
- OTP values
- card numbers
- CVV/CVC values

The following headers are not collected:

```text
Authorization
Cookie
Set-Cookie
X-Api-Key
X-Auth-Token
Proxy-Authorization
```

The Runtime does not automatically capture:

- multipart file bodies
- uploaded files
- arbitrary binary request bodies
- request bodies without a supported content type

Capture is bounded by body size, field count, value size and nesting depth.

Applications using custom names for sensitive data should review their telemetry before production deployment.

## Local spool

Events are written to a local file spool before delivery.

Default permissions are:

```text
directory: 0700
event file: 0600
```

An event is removed only after successful delivery.

A failed delivery returns the event to the queue for a later attempt.

## Laravel configuration

The default configuration works without publishing a config file.

To customize it:

```bash
php artisan vendor:publish --tag=loguard-runtime-config
```

The generated file is:

```text
config/loguard-runtime.php
```

Useful environment variables include:

```text
LOGUARD_RUNTIME_ENABLED
LOGUARD_ENV
LOGUARD_SERVICE
LOGUARD_API_KEY
LOGUARD_SPOOL_PATH
LOGUARD_SPOOL_MAX_FILES
LOGUARD_MAX_EVENT_BYTES
LOGUARD_SECURITY_CAPTURE
LOGUARD_TRACK_ALL_REQUESTS
LOGUARD_MAX_BODY_BYTES
LOGUARD_MAX_BODY_JSON_DEPTH
LOGUARD_TRUSTED_PROXIES
```

Worker-specific options:

```text
LOGUARD_BASE_URL
LOGUARD_TIMEOUT
LOGUARD_RETRIES
LOGUARD_BATCH_SIZE
LOGUARD_ALLOW_INSECURE_TRANSPORT
```

HTTPS verification is enabled by default.

`LOGUARD_ALLOW_INSECURE_TRANSPORT` should not be enabled in production.

## Trusted proxies

`X-Forwarded-For` is used only when the direct peer matches an explicitly configured trusted proxy.

Example:

```env
LOGUARD_TRUSTED_PROXIES=10.0.0.10,10.0.0.11
```

Do not use broad trusted-proxy ranges unless they match the real network topology.

## Non-Laravel applications

The Runtime core is not tied to Laravel.

Non-Laravel applications can use the core capture, event and spool components, but request integration must be added by the application or framework adapter.

Outside a detected Laravel application, the worker defaults to:

```text
/var/spool/loguard
```

Set `LOGUARD_SPOOL_PATH` when another path is required.

## Versioning

The first public Runtime releases use the `0.x` version series while support is expanded across PHP frameworks and production environments.

Pin a compatible release range in production.

## License

MIT. See [LICENSE](LICENSE).
