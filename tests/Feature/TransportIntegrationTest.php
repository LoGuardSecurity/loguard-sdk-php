<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Feature;

use LoGuard\Sdk\Exceptions\LoGuardAuthException;
use LoGuard\Sdk\Exceptions\LoGuardConnectionException;
use LoGuard\Sdk\Exceptions\LoGuardQuotaException;
use LoGuard\Sdk\Signing;
use LoGuard\Sdk\Tests\Support\MockServerProcess;
use LoGuard\Sdk\Transport;
use PHPUnit\Framework\TestCase;

/**
 * @group integration
 *
 * Requires the `php` binary on PATH (used to spin up the loopback
 * mock server) -- skips automatically if unavailable, e.g. in a
 * minimal container.
 */
final class TransportIntegrationTest extends TestCase
{
    private static ?MockServerProcess $server = null;

    public static function setUpBeforeClass(): void
    {
        if (!self::binaryAvailable('php')) {
            self::markTestSkipped('php CLI not available for the loopback mock server');
        }
        self::$server = new MockServerProcess();
    }

    public static function tearDownAfterClass(): void
    {
        self::$server?->stop();
    }

    private static function binaryAvailable(string $bin): bool
    {
        $path = trim((string) shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null'));

        return $path !== '';
    }

    public function testSuccessfulIngest(): void
    {
        $result = Transport::sendSync(
            self::$server->baseUrl() . '/v1/ingest/ok',
            ['Content-Type' => 'application/json'],
            ['events' => []],
            2.0,
            1,
            'POST',
            'test-key'
        );

        $this->assertTrue($result['ok']);
    }

    public function testRetriesOnServerErrorThenSucceeds(): void
    {
        $result = Transport::sendSync(
            self::$server->baseUrl() . '/v1/ingest/fail-twice-then-ok',
            [],
            ['events' => []],
            2.0,
            5,
            'POST',
            'test-key'
        );

        $this->assertTrue($result['ok']);
    }

    public function testExhaustsRetriesAndThrowsConnectionError(): void
    {
        $this->expectException(LoGuardConnectionException::class);
        Transport::sendSync(
            self::$server->baseUrl() . '/v1/ingest/always-500',
            [],
            ['events' => []],
            1.0,
            2,
            'POST',
            'test-key'
        );
    }

    public function test401MapsToAuthException(): void
    {
        $this->expectException(LoGuardAuthException::class);
        Transport::sendSync(self::$server->baseUrl() . '/v1/ingest/unauthorized', [], ['events' => []], 2.0, 1, 'POST', 'test-key');
    }

    public function test429QuotaBodyMapsToQuotaException(): void
    {
        $this->expectException(LoGuardQuotaException::class);
        Transport::sendSync(self::$server->baseUrl() . '/v1/ingest/quota', [], ['events' => []], 2.0, 1, 'POST', 'test-key');
    }

    public function testMalformedJsonResponseIsRejected(): void
    {
        $this->expectException(LoGuardConnectionException::class);
        Transport::sendSync(self::$server->baseUrl() . '/v1/ingest/malformed-json', [], ['events' => []], 2.0, 1, 'POST', 'test-key');
    }

    public function testOversizedResponseIsAbortedNotBuffered(): void
    {
        // A malicious/misbehaving server sending an unbounded body must
        // not be fully buffered into memory -- the transfer should abort
        // as a connection error well before MAX_RESPONSE_BYTES + anything
        // meaningful accumulates.
        $this->expectException(LoGuardConnectionException::class);
        Transport::sendSync(self::$server->baseUrl() . '/v1/ingest/oversized', [], ['events' => []], 5.0, 1, 'POST', 'test-key');
    }

    public function testRedirectIsNeverFollowed(): void
    {
        $this->expectException(LoGuardConnectionException::class);
        Transport::sendSync(self::$server->baseUrl() . '/v1/ingest/redirect', [], ['events' => []], 2.0, 1, 'POST', 'test-key');
    }
}
