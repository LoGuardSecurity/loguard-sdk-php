<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Http\ClientIp;
use PHPUnit\Framework\TestCase;

final class ClientIpTest extends TestCase
{
    public function testUntrustedPeerIgnoresForwardedFor(): void
    {
        // No trusted_proxies configured -- header must never be honored,
        // even though it's present. This is the anti-spoofing default.
        $ip = ClientIp::resolve('203.0.113.9', '9.9.9.9', []);
        $this->assertSame('203.0.113.9', $ip);
    }

    public function testTrustedProxyForwardsFirstXffEntry(): void
    {
        $ip = ClientIp::resolve('10.0.0.1', '198.51.100.7, 10.0.0.1', ['10.0.0.1']);
        $this->assertSame('198.51.100.7', $ip);
    }

    public function testTrustedProxyWithMalformedXffFallsBackToPeer(): void
    {
        $ip = ClientIp::resolve('10.0.0.1', 'not-an-ip', ['10.0.0.1']);
        $this->assertSame('10.0.0.1', $ip);
    }

    public function testCidrTrustedProxyRange(): void
    {
        $ip = ClientIp::resolve('10.0.5.42', '198.51.100.7', ['10.0.0.0/16']);
        $this->assertSame('198.51.100.7', $ip);
    }

    public function testCidrDoesNotMatchOutsideRange(): void
    {
        $ip = ClientIp::resolve('10.1.5.42', '198.51.100.7', ['10.0.0.0/16']);
        $this->assertSame('10.1.5.42', $ip);
    }

    public function testEmptyPeerFallsBackToLoopback(): void
    {
        $ip = ClientIp::resolve('', null, []);
        $this->assertSame('127.0.0.1', $ip);
    }

    public function testSpoofAttemptFromUntrustedDirectPeerIsIgnored(): void
    {
        // Attacker directly connects and sets X-Forwarded-For to an
        // arbitrary IP, hoping to be attributed to someone else.
        $ip = ClientIp::resolve('198.51.100.66', '1.2.3.4', ['10.0.0.1']);
        $this->assertSame('198.51.100.66', $ip);
    }
}
