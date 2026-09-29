<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Laravel;

use Illuminate\Support\ServiceProvider;
use LoGuard\Runtime\Dispatch\FileSpool;
use LoGuard\Runtime\EventBuilder;
use LoGuard\Runtime\Http\HttpEventFactory;

final class LoGuardRuntimeServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/loguard-runtime.php',
            'loguard-runtime'
        );

        $this->app->singleton(
            HttpEventFactory::class,
            function () {
                return new HttpEventFactory();
            }
        );

        $this->app->singleton(
            EventBuilder::class,
            function () {
                return new EventBuilder(
                    (string) config(
                        'loguard-runtime.env',
                        'production'
                    ),
                    config('loguard-runtime.service'),
                    (int) config(
                        'loguard-runtime.max_event_bytes',
                        64 * 1024
                    )
                );
            }
        );

        $this->app->singleton(
            FileSpool::class,
            function () {
                return new FileSpool(
                    (string) config(
                        'loguard-runtime.spool_path',
                        storage_path('loguard-spool')
                    ),
                    (int) config(
                        'loguard-runtime.spool_max_files',
                        10000
                    )
                );
            }
        );
    }

    public function boot()
    {
        $this->publishes(
            [
                __DIR__
                    . '/../../config/loguard-runtime.php'
                    => config_path('loguard-runtime.php'),
            ],
            'loguard-runtime-config'
        );
    }
}
