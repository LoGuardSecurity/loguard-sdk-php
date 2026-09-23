<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Config;
use LoGuard\Sdk\Exceptions\LoGuardAuthException;
use LoGuard\Sdk\Exceptions\LoGuardValidationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testRequiresApiKey(): void
    {
        $this->expectException(LoGuardAuthException::class);
        new Config('');
    }

    public function testRequiresApiKeyNotJustWhitespace(): void
    {
        $this->expectException(LoGuardAuthException::class);
        new Config('   ');
    }

    public function testRejectsPlainHttpByDefault(): void
    {
        $this->expectException(LoGuardValidationException::class);
        new Config('lg_live_x', 'http://loguard.org');
    }

    public function testAllowsPlainHttpWhenExplicitlyOptedIn(): void
    {
        $config = @new Config('lg_live_x', 'http://loguard.internal', 'production', 10.0, 3, null, true);
        $this->assertSame('http://loguard.internal', $config->baseUrl);
        $this->assertTrue($config->allowInsecureTransport);
    }

    public function testTrailingSlashIsStripped(): void
    {
        $config = new Config('lg_live_x', 'https://api.loguard.org/');
        $this->assertSame('https://api.loguard.org', $config->baseUrl);
        $this->assertSame('https://api.loguard.org/v1/ingest', $config->ingestUrl());
    }

    public function testSafeDefaults(): void
    {
        $config = new Config('lg_live_x');
        $this->assertSame('https://api.loguard.org', $config->baseUrl);
        $this->assertSame('production', $config->env);
        $this->assertSame(3.0, $config->timeout);
        $this->assertSame(2, $config->retries);
        $this->assertSame(64 * 1024, $config->maxEventBytes);
    }

    #[DataProvider('invalidSettings')]
    public function testRejectsUnsafeBounds(float $timeout, int $retries, int $maxBytes): void
    {
        $this->expectException(LoGuardValidationException::class);
        new Config('lg_live_x', timeout: $timeout, retries: $retries, maxEventBytes: $maxBytes);
    }

    public static function invalidSettings(): array
    {
        return [
            'zero timeout' => [0.0, 2, 65536],
            'too many attempts' => [3.0, 99, 65536],
            'unbounded event' => [3.0, 2, 2 * 1024 * 1024],
        ];
    }

    public function testRejectsCredentialsInBaseUrl(): void
    {
        $this->expectException(LoGuardValidationException::class);
        new Config('lg_live_x', 'https://user:pass@example.test');
    }

    public function testFromArray(): void
    {
        $config = Config::fromArray([
            'api_key' => 'lg_live_x',
            'base_url' => 'https://example.test',
            'env' => 'staging',
            'timeout' => 5.5,
            'retries' => 2,
            'service' => 'checkout-api',
        ]);

        $this->assertSame('https://example.test', $config->baseUrl);
        $this->assertSame('staging', $config->env);
        $this->assertSame(5.5, $config->timeout);
        $this->assertSame(2, $config->retries);
        $this->assertSame('checkout-api', $config->service);
    }
}
