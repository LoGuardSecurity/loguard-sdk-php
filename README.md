# LoGuard SDK for PHP

The official PHP client for sending security events to LoGuard. The core package
does not depend on a framework. Adapters are included for Laravel, PSR-15 and
CodeIgniter 3.

## Requirements

- PHP 8.1 or newer
- cURL, JSON and mbstring extensions
- HTTPS access to the LoGuard API

## Installation

```bash
composer require loguard/loguard-sdk
```

## Plain PHP

```php
use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;

$client = new Client(new Config(
    apiKey: getenv('LOGUARD_API_KEY'),
    service: 'checkout-api'
));

$client->event(
    type: 'login_failed',
    ip: $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
    path: '/login',
    statusCode: 401
);
```

`event()` is synchronous. Use it from workers, commands or flows where the
result is required. For a web request, prefer `eventAsync()` with a durable
spool or a framework queue.

## Durable delivery

```php
use LoGuard\Sdk\Dispatch\FileSpool;

$spool = new FileSpool('/var/spool/loguard');
$client = new Client($config, eventSink: $spool);
$client->eventAsync('http_error', $ip, $path, 403);
```

The request only writes a small file using an atomic rename. A separate worker
can drain the directory:

```php
use LoGuard\Sdk\Dispatch\SpoolWorker;

$worker = new SpoolWorker($client, $spool);
$sent = $worker->runOnce(50);
```

Run the worker from systemd, Supervisor, cron or your existing job runner. Use a
directory writable only by the application user. The spool is bounded by
default and returns `false` when full; register `Client::onDropped()` to send
that condition to your metrics or logs.

## HTTP capture

Automatic capture is built around three framework-neutral objects:

- `RequestContext` describes the completed request and response.
- `CapturePolicy` says which responses and fields may be recorded.
- `HttpEventFactory` creates the event.

Query parameters, request bodies and headers are opt-in. Common secret field
names are always removed. JSON bodies are subject to byte and nesting limits,
and every event is sanitized again before signing.

### Laravel

Publish the configuration and register the middleware:

```bash
php artisan vendor:publish --tag=loguard-config
```

```php
\LoGuard\Sdk\Laravel\Http\Middleware\LoGuardMiddleware::class
```

For production, set `LOGUARD_QUEUE_EVENTS=true` and run a Laravel queue worker.
The queue job performs one transport attempt; Laravel owns the retry policy.

### PSR-15

Install your preferred PSR-7 implementation together with:

```bash
composer require psr/http-message psr/http-server-middleware
```

Add `LoGuard\Sdk\Psr15\LoGuardMiddleware` after routing so the adapter can
read the optional `route.name` request attribute.

### CodeIgniter 3

Create the client in application bootstrap and register
`LoGuard\Sdk\CodeIgniter3\LoGuardHook::capture` as a `post_system` hook.
Keep the SDK instance in your dependency container or a small application
factory. Do not put the API key in `hooks.php`; read it from the environment.

The supplied CI3 hook uses the same capture policy as the other adapters. It
does not contain project-specific routes, authentication logic or Blynex code.

## Privacy defaults

- No request headers, query parameters or body fields are captured by default.
- Authorization, cookies, tokens, passwords and payment secrets are denied even
  if mistakenly placed in an allowlist.
- Arbitrary `meta` is recursively filtered, bounded and truncated.
- Forwarded addresses are trusted only through configured proxy CIDRs.
- User IDs should be opaque internal identifiers. Do not send email addresses.

## Failure behavior

Synchronous calls throw typed LoGuard exceptions. Asynchronous capture is
fail-open: SDK failures do not change the application response. Network
redirects are never followed, TLS verification cannot be disabled, response
bodies are bounded, and invalid JSON is rejected.

Defaults are deliberately conservative:

- request timeout: 3 seconds
- attempts per synchronous send: 2
- maximum serialized event: 64 KiB
- in-memory batch: 50 events

## Testing

```bash
composer install
composer test
composer phpstan
```

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and
[docs/OPERATIONS.md](docs/OPERATIONS.md) for rollout and worker guidance.
