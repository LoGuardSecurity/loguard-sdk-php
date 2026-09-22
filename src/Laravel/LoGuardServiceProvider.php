<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Laravel;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;
use LoGuard\Sdk\Event;

/**
 * Registers the LoGuard SDK with a Laravel application.
 *
 * Auto-discovered via composer.json's extra.laravel.providers — no
 * manual registration needed on Laravel 5.5+. The core SDK
 * (LoGuard\Sdk\Client) has zero Laravel dependencies; this provider
 * is the only place that couples the two together.
 */
final class LoGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/loguard.php', 'loguard');

        $this->app->singleton(Client::class, function (Application $app): Client {
            $config = (array) $app['config']->get('loguard', []);

            // Disabled installs (no api_key / LOGUARD_ENABLED=false) still
            // get a real Client so DI + the middleware never has to
            // null-check — event delivery is what's skipped (see
            // LoGuardMiddleware::terminate()), not client construction.
            // A syntactically valid placeholder key keeps Config's
            // validation happy without ever being used to sign a request
            // that's actually sent.
            if (empty($config['api_key'])) {
                $config['api_key'] = 'lg_disabled_placeholder';
            }

            $client = new Client(Config::fromArray($config));

            // [NEW — audit remediation] Event loss must be observable, not
            // silent. eventAsync()'s in-memory buffer drops the OLDEST
            // queued event once full (see Client::$maxQueueSize) --
            // without this, that drop would never surface anywhere. An
            // application can still override this by calling
            // $client->onDropped() again with its own callback (only the
            // last registration wins).
            $client->onDropped(function (Event $event): void {
                Log::warning('loguard: event dropped (in-memory queue full)', [
                    'type' => $event->type,
                    'path' => $event->path,
                ]);
            });

            return $client;
        });

        $this->app->alias(Client::class, 'loguard');
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../../config/loguard.php' => $this->app->configPath('loguard.php'),
        ], 'loguard-config');
    }

    /**
     * @return string[]
     */
    public function provides(): array
    {
        return [Client::class, 'loguard'];
    }
}
