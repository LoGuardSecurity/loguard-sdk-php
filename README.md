# LoGuard PHP SDK

Official PHP SDK for LoGuard security monitoring and threat detection,
with first-class Laravel integration. Framework-agnostic core — works
in plain PHP, Laravel, Symfony, or any other stack.

Built to be behaviorally consistent with the existing LoGuard SDKs
(Python, Node.js, Go, C#): same wire protocol, same validation rules,
same error taxonomy, same retry/backoff behavior. If you already use
LoGuard from another service in a polyglot stack, this SDK will feel
identical.

## Installation

```bash
composer require loguard/loguard-sdk
```

Requires PHP 8.1+, `ext-curl`, `ext-json`, `ext-mbstring` (all part of
a standard PHP install). No other runtime dependencies.

## Quick start (plain PHP)

```php
use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;

$loguard = new Client(new Config(
    apiKey: getenv('LOGUARD_API_KEY'),
    baseUrl: getenv('LOGUARD_BASE_URL') ?: 'https://api.loguard.org',
    env: getenv('LOGUARD_ENV') ?: 'production',
));

// Blocking — waits for the LoGuard API response.
$result = $loguard->event(
    type: 'login_failed',
    ip: '1.2.3.4',
    path: '/api/login',
    statusCode: 401,
    userId: 'user_123',
    meta: ['method' => 'POST'],
);

echo $result->inserted, ' accepted', PHP_EOL;
// $result->alertsFired / $result->alerts reflect ONLY what the server
// returned synchronously in THIS response. If detection on the backend
// runs asynchronously, this will be 0 on every call regardless of
// whether a detector fires moments later -- it is not confirmation that
// nothing was detected. See IngestResult's docblock, and use LoGuard's
// Verification feature (in the dashboard) to actually confirm that a
// detection scenario fires end-to-end, not this field.

// Non-blocking — buffered in memory, flushed automatically at
// process shutdown (or call $loguard->flush() explicitly).
$loguard->eventAsync(
    type: 'http_request',
    ip: '1.2.3.4',
    path: '/api/users',
    statusCode: 200,
);

// Multiple events in one request.
$result = $loguard->eventBatch([
    ['type' => 'http_request', 'ip' => '1.2.3.4', 'path' => '/', 'status_code' => 200],
    ['type' => 'login_failed', 'ip' => '1.2.3.4', 'path' => '/login', 'status_code' => 401],
    ['type' => 'http_request', 'ip' => '5.6.7.8', 'path' => '/.env', 'status_code' => 404],
]);
```

### Event types

| Type             | Description               |
|------------------|----------------------------|
| `http_request`   | Incoming HTTP request      |
| `login_failed`   | Failed authentication      |
| `login_success`  | Successful login           |
| `forbidden`      | Access denied              |
| `waf_block`      | Request blocked by a WAF   |
| `bot_detected`   | Bot traffic detected       |

## Laravel

The service provider is auto-discovered — nothing to register manually.

### 1. Configure

```bash
php artisan vendor:publish --tag=loguard-config
```

```env
LOGUARD_API_KEY=lg_live_xxx
LOGUARD_ENV=production
LOGUARD_QUEUE_EVENTS=true
```

### 2. Add the middleware

Laravel 11+ (`bootstrap/app.php`):

```php
use LoGuard\Sdk\Laravel\Http\Middleware\LoGuardMiddleware;

->withMiddleware(function (Middleware $middleware) {
    $middleware->append(LoGuardMiddleware::class);
})
```

Laravel 10 and earlier (`app/Http/Kernel.php`):

```php
protected $middleware = [
    // ...
    \LoGuard\Sdk\Laravel\Http\Middleware\LoGuardMiddleware::class,
];
```

This tracks HTTP error responses (configurable via `loguard.middleware.track_statuses`,
default `400,401,403,404,429,500,502,503`) as LoGuard events automatically —
**all reported as the generic `http_error` type, including 401**. The
middleware only sees a status code, not *why* the app returned it, so it
never guesses `login_failed` from a 401 alone (an expired API token on an
already-authenticated user would look identical). Set
`loguard.middleware.track_all_requests` (env `LOGUARD_TRACK_ALL_REQUESTS`)
to `true` to report every response regardless of status — off by default,
since it meaningfully changes event volume/plan usage.

### Reporting a confirmed failed login

Call this from your own authentication code, where "this really was a
login attempt, and it really failed" is actually known — not inferred
from a status code:

```php
use LoGuard\Sdk\Laravel\Facades\LoGuard;

LoGuard::recordLoginFailure(ip: $request->ip(), path: '/login', userId: $attemptedUserId);
```

This is a second, independent signal, not a replacement for the
middleware's generic `http_error` event — both firing for the same
request is not double-counting, it's two different claims (raw HTTP
telemetry vs. a confirmed business event).

### Query/body capture (optional, off by default, per named route)

```php
// config/loguard.php
'middleware' => [
    'track_query_params' => [
        'search.index' => ['q', 'category'], // Route::name('search.index')
    ],
    'track_body_json_paths' => [
        'auth.login' => ['email'], // dot-path into the JSON body; never list "password" -- stripped anyway
    ],
],
```

Requires a **named route** (`Route::name(...)`) — the allowlist key is the
route name, not the raw path, so a dynamic segment (`/users/{id}`) doesn't
need one entry per id. A field whose name matches a secret pattern
(`password`, `token`, `secret`, `api_key`, `cookie`, ...) is stripped even
if explicitly listed, at any nesting depth (`LoGuard\Sdk\Http\FieldPolicy::FORBIDDEN_FIELD_PATTERNS`).
Only `application/json` bodies are ever parsed — multipart/form-data,
file uploads, and any other content type are skipped outright, never
partially processed. **This cannot catch a secret embedded inside an
otherwise innocuous field's free-text value** (e.g. a token pasted into a
"comment" field) — field-name-based redaction is not content scanning,
and should not be described to end users as such.

### 3. Use directly (facade or DI)

```php
use LoGuard\Sdk\Laravel\Facades\LoGuard;

LoGuard::event(
    type: 'waf_block',
    ip: $request->ip(),
    path: $request->path(),
    statusCode: 403,
);
```

Or inject `LoGuard\Sdk\Client` like any other service.

### Queue-backed delivery (recommended for production)

Set `LOGUARD_QUEUE_EVENTS=true` and run a queue worker. Events captured
by the middleware are then dispatched as a real Laravel job
(`LoGuard\Sdk\Laravel\Jobs\SendLoGuardEvents`) instead of being flushed
inline at request end — delivery survives worker restarts, gets
Laravel's own retry/backoff, and adds **zero** latency to the HTTP
response, at the cost of needing a running queue worker.

Without queueing, delivery happens from `terminate()`, which (on
PHP-FPM, via `fastcgi_finish_request`) still runs after the response
has been sent to the browser — but it runs inside the same web worker
process, so a slow/unreachable LoGuard API can hold that worker for up
to `timeout * retries` seconds. Queueing avoids that entirely.

### Forwarding request headers (optional, off by default)

A handful of severe vulnerabilities (ShellShock, ProxyLogon) only show
up inside specific HTTP headers. By default, nothing beyond what the
SDK needs internally (`X-Forwarded-For`, only to resolve the real
client IP, never forwarded as data) is sent to LoGuard.

```php
// config/loguard.php
'middleware' => [
    'track_headers' => \LoGuard\Sdk\Http\HeaderPolicy::KNOWN_EXPLOIT_HEADERS,
    // or your own list, e.g. ['User-Agent', 'Referer', 'X-My-Header'],
],
```

`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`,
and `Proxy-Authorization` are **never** forwarded, even if listed here —
enforced in code (`HeaderPolicy::FORBIDDEN_HEADERS`), not just documented.

### Trusting a reverse proxy

`X-Forwarded-For` is ignored unless the direct TCP peer is a proxy you
explicitly name (secure-by-default — otherwise any visitor could spoof
their tracked IP):

```env
LOGUARD_TRUSTED_PROXIES=10.0.0.0/8,203.0.113.5
```

## Error handling

All SDK errors extend `LoGuard\Sdk\Exceptions\LoGuardException`:

```php
use LoGuard\Sdk\Exceptions\{
    LoGuardAuthException,      // invalid API key / expired subscription
    LoGuardQuotaException,     // monthly event quota exceeded
    LoGuardConnectionException,// network/server error, retries exhausted
    LoGuardValidationException,// malformed event data
    LoGuardNotFoundException,
    LoGuardConflictException,
};

try {
    $loguard->event(type: 'login_failed', ip: $ip, path: $path, statusCode: 401);
} catch (LoGuardQuotaException $e) {
    // upgrade prompt, or just stop sending until next month
} catch (LoGuardConnectionException $e) {
    // LoGuard is unreachable — this is not your app's fault, log and move on
}
```

`eventAsync()` never throws — failures are dropped silently (matching
every other LoGuard SDK's fire-and-forget semantics), which is why the
queue-backed Laravel path is preferable when you need delivery
guarantees.

## Retry behavior

Requests retry on `500`, `502`, `503`, `504` and connection-level
failures (DNS, TLS, timeout, reset), up to `retries` attempts
(default 3) with linear backoff (`0.4s * attempt`). `429` is mapped to
`LoGuardQuotaException` (quota) or treated as a non-retried rate-limit
error, matching the other SDKs — LoGuard's own backend is responsible
for rate-limit pacing, not client-side retry-until-success.

## Performance

- Zero HTTP dependency: built on `ext-curl`, already present in nearly
  every PHP install.
- `event()`/`eventBatch()` are the only blocking calls; `eventAsync()`
  never blocks the caller.
- Response bodies are capped at 5 MiB and streamed via a curl write
  callback — a misbehaving or malicious server response can't exhaust
  your worker's memory.
- No autoloading of the Laravel integration unless Laravel is present
  (separate namespace, no `require` from the core classes).

## Security

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full audit notes —
attack classes considered, what's mitigated, and what's out of scope
for a client SDK.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `LoGuardValidationException: base_url must use https://` | You passed a non-HTTPS `base_url` without `allowInsecureTransport: true`. Only use that flag for local development. |
| Events silently not arriving via `eventAsync()`/middleware | Check `loguard.enabled` (is an API key configured?), then check application logs — failures are swallowed by design but still `report()`-ed in the Laravel middleware. |
| `LoGuardAuthException: Invalid API key` | Confirm `LOGUARD_API_KEY` in the environment actually reaching your app matches the dashboard value (no leading/trailing whitespace — `Config` trims it, but double check `.env` quoting). |
| Slow responses after adding the middleware | You're not on `LOGUARD_QUEUE_EVENTS=true` and either PHP-FPM isn't finishing the request before `terminate()` runs, or LoGuard itself is slow — lower `LOGUARD_TIMEOUT`/`LOGUARD_RETRIES` or switch to queueing. |

## Production deployment checklist

- [ ] `LOGUARD_API_KEY` set via secret manager / environment, never committed.
- [ ] `LOGUARD_BASE_URL` is `https://` (default) — do not set `LOGUARD_ALLOW_INSECURE_TRANSPORT` in production.
- [ ] `LOGUARD_QUEUE_EVENTS=true` with a supervised queue worker, so LoGuard delivery never competes with request latency.
- [ ] `LOGUARD_TRUSTED_PROXIES` set to your actual load balancer/proxy IPs if you're behind one — otherwise IP-based alerting can be trivially spoofed.
- [ ] `track_headers` left empty unless you've reviewed exactly which headers you're opting in to forward.
