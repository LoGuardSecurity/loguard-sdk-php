<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use LoGuard\Sdk\IngestResult;

/**
 * @method static IngestResult event(string $type, string $ip, string $path, int $statusCode, ?string $userId = null, ?string $service = null, array $meta = [], ?\DateTimeInterface $ts = null)
 * @method static IngestResult eventBatch(array $events)
 * @method static void eventAsync(string $type, string $ip, string $path, int $statusCode, ?string $userId = null, ?string $service = null, array $meta = [], ?\DateTimeInterface $ts = null)
 * @method static void flush()
 * @method static void shutdown()
 *
 * @see \LoGuard\Sdk\Client
 */
final class LoGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'loguard';
    }
}
