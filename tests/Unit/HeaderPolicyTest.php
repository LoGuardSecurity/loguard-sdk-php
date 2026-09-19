<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Http\HeaderPolicy;
use PHPUnit\Framework\TestCase;

final class HeaderPolicyTest extends TestCase
{
    public function testForbiddenHeadersAreAlwaysStrippedEvenIfRequested(): void
    {
        $sanitized = HeaderPolicy::sanitizeRequested([
            'Authorization', 'Cookie', 'X-Api-Key', 'X-Auth-Token',
            'Proxy-Authorization', 'Set-Cookie', 'User-Agent',
        ]);

        $this->assertSame(['user-agent'], $sanitized);
    }

    public function testCollectReturnsEmptyWhenNoHeadersRequested(): void
    {
        $collected = HeaderPolicy::collect([], fn (string $n) => 'should-not-be-called');
        $this->assertSame([], $collected);
    }

    public function testCollectTruncatesOversizedValues(): void
    {
        $huge = str_repeat('x', 5000);
        $collected = HeaderPolicy::collect(['user-agent'], fn (string $n) => $huge);
        $this->assertSame(512, strlen($collected['user-agent']));
    }

    public function testCollectSkipsAbsentHeaders(): void
    {
        $collected = HeaderPolicy::collect(['referer'], fn (string $n) => null);
        $this->assertSame([], $collected);
    }

    public function testSanitizeDedupesCaseInsensitively(): void
    {
        $sanitized = HeaderPolicy::sanitizeRequested(['Referer', 'referer', 'REFERER']);
        $this->assertSame(['referer'], $sanitized);
    }
}
