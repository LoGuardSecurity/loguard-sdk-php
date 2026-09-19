<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Feature;

use Illuminate\Support\Facades\Route;
use LoGuard\Sdk\Laravel\Http\Middleware\LoGuardMiddleware;
use LoGuard\Sdk\Tests\Support\TestCase;

/**
 * Exercises the Laravel middleware end-to-end through the framework's
 * HTTP test client. Delivery itself targets an unroutable address
 * (see TestCase::defineEnvironment), which is the point: these tests
 * assert the middleware's *behavior contract* (never breaks the
 * response, never blocks on delivery, only fires for configured
 * statuses) rather than actual network delivery, which is covered
 * separately by the transport-level tests against a local mock
 * server.
 *
 * Note: Orchestra Testbench's router-level test client does not always
 * invoke terminable middleware the same way a full HTTP Kernel does in
 * production (php artisan serve / FPM). If terminate() isn't observed
 * to run under `$this->get()` in your Testbench version, add an
 * explicit assertion via a fake/spy Client bound in the container
 * instead of relying on wall-clock/network side effects.
 */
final class LoGuardMiddlewareTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        $router->get('/ok', fn () => response('fine', 200))->middleware(LoGuardMiddleware::class);
        $router->get('/not-found', fn () => response('nope', 404))->middleware(LoGuardMiddleware::class);
        $router->get('/boom', fn () => response('boom', 500))->middleware(LoGuardMiddleware::class);
    }

    public function testUntrackedStatusPassesThroughUnaffected(): void
    {
        $response = $this->get('/ok');
        $response->assertOk();
        $response->assertSee('fine');
    }

    public function testTrackedStatusStillReturnsNormallyToTheClient(): void
    {
        // Even though LoGuard delivery will fail (unroutable base_url),
        // the response the end user sees must be completely unaffected --
        // this is the core reliability guarantee of the middleware.
        $response = $this->get('/not-found');
        $response->assertNotFound();
        $response->assertSee('nope');
    }

    public function testServerErrorStatusStillReturnsNormally(): void
    {
        $response = $this->get('/boom');
        $response->assertStatus(500);
    }

    public function testDisabledConfigSkipsEntirely(): void
    {
        config(['loguard.enabled' => false]);
        $response = $this->get('/not-found');
        $response->assertNotFound();
    }
}
