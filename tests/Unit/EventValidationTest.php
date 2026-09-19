<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;
use LoGuard\Sdk\Exceptions\LoGuardValidationException;
use PHPUnit\Framework\TestCase;

/**
 * Validation happens before any network I/O, so these run fully
 * offline even though Client normally talks to the LoGuard API.
 */
final class EventValidationTest extends TestCase
{
    private function client(): Client
    {
        // Unreachable base_url is fine: validation errors are raised
        // before Transport is ever invoked.
        return new Client(new Config('lg_test_key', 'https://127.0.0.1:1'));
    }

    public function testRejectsEmptyType(): void
    {
        $this->expectException(LoGuardValidationException::class);
        $this->client()->event('', '1.2.3.4', '/login', 401);
    }

    public function testRejectsEmptyIp(): void
    {
        $this->expectException(LoGuardValidationException::class);
        $this->client()->event('login_failed', '', '/login', 401);
    }

    public function testRejectsEmptyPath(): void
    {
        $this->expectException(LoGuardValidationException::class);
        $this->client()->event('login_failed', '1.2.3.4', '', 401);
    }

    /** @dataProvider invalidStatusCodes */
    public function testRejectsOutOfRangeStatusCode(int $status): void
    {
        $this->expectException(LoGuardValidationException::class);
        $this->client()->event('login_failed', '1.2.3.4', '/login', $status);
    }

    public static function invalidStatusCodes(): array
    {
        return [[99], [600], [-1], [0], [10000]];
    }

    public function testPathGetsLeadingSlashAdded(): void
    {
        // No setAccessible() call needed: reflection has been accessible
        // by default since PHP 8.1 (setAccessible() is a deprecated-as-of-
        // 8.5 no-op on this SDK's supported PHP range).
        $ref = new \ReflectionMethod(Client::class, 'buildEvent');
        $event = $ref->invoke($this->client(), 'http_request', '1.2.3.4', 'no-leading-slash', 200, null, null, [], null);
        $this->assertSame('/no-leading-slash', $event->path);
    }

    public function testPathIsTruncatedTo1024Chars(): void
    {
        // No setAccessible() call needed: reflection has been accessible
        // by default since PHP 8.1 (setAccessible() is a deprecated-as-of-
        // 8.5 no-op on this SDK's supported PHP range).
        $ref = new \ReflectionMethod(Client::class, 'buildEvent');
        $event = $ref->invoke($this->client(), 'http_request', '1.2.3.4', '/' . str_repeat('a', 2000), 200, null, null, [], null);
        $this->assertSame(1024, strlen($event->path));
    }

    public function testTypeIsLowercasedAndTruncated(): void
    {
        // No setAccessible() call needed: reflection has been accessible
        // by default since PHP 8.1 (setAccessible() is a deprecated-as-of-
        // 8.5 no-op on this SDK's supported PHP range).
        $ref = new \ReflectionMethod(Client::class, 'buildEvent');
        $event = $ref->invoke($this->client(), str_repeat('AB', 100), '1.2.3.4', '/x', 200, null, null, [], null);
        $this->assertSame(64, strlen($event->type));
        $this->assertSame(strtolower($event->type), $event->type);
    }

    public function testMetaAlwaysCarriesEnv(): void
    {
        // No setAccessible() call needed: reflection has been accessible
        // by default since PHP 8.1 (setAccessible() is a deprecated-as-of-
        // 8.5 no-op on this SDK's supported PHP range).
        $ref = new \ReflectionMethod(Client::class, 'buildEvent');
        $event = $ref->invoke($this->client(), 'http_request', '1.2.3.4', '/x', 200, null, null, ['custom' => 'value'], null);
        $this->assertSame('production', $event->meta['env']);
        $this->assertSame('value', $event->meta['custom']);
    }
}
