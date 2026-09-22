<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;
use LoGuard\Sdk\Event;
use PHPUnit\Framework\TestCase;

/**
 * Client-level regression coverage for the audit-remediation fix:
 * login_failed must only ever be produced by an explicit call, never
 * inferred from a status code by the Client itself. (The middleware-level
 * end-to-end version of this same invariant lives in
 * tests/Feature/MiddlewareEventContractTest.php.)
 */
final class LoginFailureSignalTest extends TestCase
{
    private function client(): Client
    {
        return new Client(new Config('lg_test_key', 'https://127.0.0.1:1'));
    }

    /** @return Event[] */
    private function pendingOf(Client $client): array
    {
        $ref = new \ReflectionProperty(Client::class, 'pending');

        return $ref->getValue($client);
    }

    public function testRecordLoginFailureProducesLoginFailedType(): void
    {
        $client = $this->client();
        $client->recordLoginFailure('1.2.3.4', '/login', 'user_1');

        $pending = $this->pendingOf($client);
        $this->assertCount(1, $pending);
        $this->assertSame(Event::class, get_class($pending[0]));
        $this->assertSame('login_failed', $pending[0]->type);
        $this->assertSame(401, $pending[0]->statusCode);
        $this->assertSame('user_1', $pending[0]->userId);
    }

    public function testRecordLoginFailureDefaultsPathToLogin(): void
    {
        $client = $this->client();
        $client->recordLoginFailure('1.2.3.4');

        $pending = $this->pendingOf($client);
        $this->assertSame('/login', $pending[0]->path);
    }

    public function testGenericHttpEventWithStatus401DoesNotBecomeLoginFailed(): void
    {
        // There is no code path anywhere in Client that promotes a plain
        // eventAsync(..., statusCode: 401, ...) call to type=login_failed --
        // this test locks that absence at the Client level.
        $client = $this->client();
        $client->eventAsync('http_error', '1.2.3.4', '/api/resource', 401);

        $pending = $this->pendingOf($client);
        $this->assertCount(1, $pending);
        $this->assertSame('http_error', $pending[0]->type);
    }
}
