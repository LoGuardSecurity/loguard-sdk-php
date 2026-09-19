<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Config;
use LoGuard\Sdk\Exceptions\LoGuardAuthException;
use LoGuard\Sdk\Exceptions\LoGuardValidationException;
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
        $config = new Config('lg_live_x', 'https://loguard.org/');
        $this->assertSame('https://loguard.org', $config->baseUrl);
        $this->assertSame('https://loguard.org/v1/ingest', $config->ingestUrl());
    }

    public function testDefaultsMatchOtherSdks(): void
    {
        $config = new Config('lg_live_x');
        $this->assertSame('https://loguard.org', $config->baseUrl);
        $this->assertSame('production', $config->env);
        $this->assertSame(10.0, $config->timeout);
        $this->assertSame(3, $config->retries);
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
