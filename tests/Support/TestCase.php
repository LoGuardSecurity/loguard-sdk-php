<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Support;

use LoGuard\Sdk\Laravel\LoGuardServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [LoGuardServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('loguard.api_key', 'lg_test_key');
        $app['config']->set('loguard.enabled', true);
        $app['config']->set('loguard.base_url', 'https://127.0.0.1:65535'); // unroutable on purpose
        $app['config']->set('loguard.queue_events', false);
    }
}
