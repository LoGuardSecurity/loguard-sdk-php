<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Feature;

use Illuminate\Support\Facades\Route;
use LoGuard\Sdk\Laravel\Http\Middleware\LoGuardMiddleware;
use LoGuard\Sdk\Laravel\LoGuardServiceProvider;
use LoGuard\Sdk\Tests\Support\MockServerProcess;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

/**
 * @group integration
 *
 * End-to-end regression coverage for the audit-remediation changes:
 * asserts on the ACTUAL JSON body the middleware sends over real HTTP
 * to a loopback mock server (via `/v1/ingest/capture`, see
 * MockServerProcess::lastCapturedPayload()) rather than reconstructing
 * what the code "should" send -- this is what would have caught the
 * original "401 -> login_failed" bug directly, instead of only at the
 * unit level.
 *
 * Requires the `php` binary on PATH (spins up the loopback mock
 * server) -- skips automatically if unavailable.
 */
final class MiddlewareEventContractTest extends OrchestraTestCase
{
    private static ?MockServerProcess $server = null;

    public static function setUpBeforeClass(): void
    {
        if (trim((string) shell_exec('command -v php 2>/dev/null')) === '') {
            self::markTestSkipped('php CLI not available for the loopback mock server');
        }
        self::$server = new MockServerProcess();
    }

    public static function tearDownAfterClass(): void
    {
        self::$server?->stop();
    }

    protected function setUp(): void
    {
        parent::setUp();
        MockServerProcess::clearCapture();
    }

    protected function getPackageProviders($app): array
    {
        return [LoGuardServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('loguard.api_key', 'lg_test_key');
        $app['config']->set('loguard.enabled', true);
        // Config::ingestUrl() always appends '/v1/ingest' to base_url, and
        // the mock router's '/v1/ingest' case captures the raw request
        // body -- same real code path (Config -> Transport -> Signing) as
        // production, nothing bypassed.
        $app['config']->set('loguard.base_url', self::$server->baseUrl());
        $app['config']->set('loguard.queue_events', false);
    }

    protected function defineRoutes($router): void
    {
        $router->get('/needs-auth', fn () => response('nope', 401))->middleware(LoGuardMiddleware::class);
        $router->get('/missing', fn () => response('nope', 404))->middleware(LoGuardMiddleware::class);
        $router->get('/ok', fn () => response('fine', 200))->middleware(LoGuardMiddleware::class);

        $router->get('/search', fn () => response('results', 400))
            ->middleware(LoGuardMiddleware::class)
            ->name('search.index');

        $router->post('/login', fn () => response('bad creds', 401))
            ->middleware(LoGuardMiddleware::class)
            ->name('auth.login');
    }

    private function capturedPayload(): ?array
    {
        return MockServerProcess::lastCapturedPayload();
    }

    public function testPlain401IsReportedAsGenericHttpErrorNotLoginFailed(): void
    {
        config(['loguard.middleware.track_statuses' => [401, 404]]);

        $this->get('/needs-auth');

        $payload = $this->capturedPayload();
        $this->assertNotNull($payload, 'middleware must have delivered an event to the mock server');
        $event = $payload['events'][0] ?? null;
        $this->assertNotNull($event);
        $this->assertSame('http_error', $event['type'], 'a plain 401 must never be auto-classified as login_failed');
        $this->assertSame(401, $event['status_code']);
    }

    public function test404IsAlsoReportedAsGenericHttpError(): void
    {
        config(['loguard.middleware.track_statuses' => [401, 404]]);

        $this->get('/missing');

        $event = $this->capturedPayload()['events'][0] ?? null;
        $this->assertNotNull($event);
        $this->assertSame('http_error', $event['type']);
    }

    public function testUntrackedStatusIsNotReportedByDefault(): void
    {
        config(['loguard.middleware.track_statuses' => [401, 404]]);
        config(['loguard.middleware.track_all_requests' => false]);

        $this->get('/ok'); // 200, not in track_statuses, track_all_requests off

        $this->assertNull($this->capturedPayload(), 'a 200 response must not be reported unless track_all_requests is enabled');
    }

    public function testTrackAllRequestsOptInReportsEverythingRegardlessOfStatus(): void
    {
        config(['loguard.middleware.track_statuses' => [401, 404]]); // deliberately does NOT include 200
        config(['loguard.middleware.track_all_requests' => true]);

        $this->get('/ok'); // 200

        $event = $this->capturedPayload()['events'][0] ?? null;
        $this->assertNotNull($event, 'track_all_requests=true must report a 200 even though it is absent from track_statuses');
        $this->assertSame(200, $event['status_code']);
    }

    public function testQueryCaptureOnlyIncludesAllowlistedFieldAndNeverForbiddenNames(): void
    {
        config(['loguard.middleware.track_statuses' => [400]]);
        config(['loguard.middleware.track_query_params' => [
            'search.index' => ['q'], // 'password' deliberately NOT allowlisted
        ]]);

        $this->get('/search?q=hello&password=leak-me');

        $event = $this->capturedPayload()['events'][0] ?? null;
        $this->assertNotNull($event);
        $this->assertSame('hello', $event['meta']['query']['q'] ?? null);
        $this->assertArrayNotHasKey('password', $event['meta']['query'] ?? []);
    }

    public function testBodyCaptureStripsPasswordFieldEvenIfAllowlistedByMistake(): void
    {
        config(['loguard.middleware.track_statuses' => [401]]);
        config(['loguard.middleware.track_body_json_paths' => [
            'auth.login' => ['email', 'password'], // 'password' listed by mistake
        ]]);

        $this->postJson('/login', ['email' => 'a@b.com', 'password' => 'hunter2']);

        $event = $this->capturedPayload()['events'][0] ?? null;
        $this->assertNotNull($event);
        $this->assertSame('a@b.com', $event['meta']['body']['email'] ?? null);
        $this->assertArrayNotHasKey('password', $event['meta']['body'] ?? []);
    }

    public function testBodyCaptureIsOffWhenNotConfiguredForThatRoute(): void
    {
        config(['loguard.middleware.track_statuses' => [401]]);
        config(['loguard.middleware.track_body_json_paths' => []]); // nothing configured

        $this->postJson('/login', ['email' => 'a@b.com', 'password' => 'hunter2']);

        $event = $this->capturedPayload()['events'][0] ?? null;
        $this->assertNotNull($event);
        $this->assertArrayNotHasKey('body', $event['meta'] ?? []);
    }
}
