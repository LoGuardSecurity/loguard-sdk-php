<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Privacy\Sanitizer;
use PHPUnit\Framework\TestCase;

final class SanitizerTest extends TestCase
{
    public function testRemovesSecretsAtEveryDepth(): void
    {
        $result = (new Sanitizer())->meta([
            'route' => 'checkout',
            'nested' => ['api_token' => 'secret', 'safe' => 'ok'],
            'authorization_header' => 'Bearer secret',
        ]);

        $this->assertSame(['route' => 'checkout', 'nested' => ['safe' => 'ok']], $result);
    }

    public function testBoundsStringsCollectionsAndDepth(): void
    {
        $result = (new Sanitizer(2, 2, 4))->meta([
            'long' => 'abcdef',
            'items' => ['a' => 1, 'b' => 2, 'c' => 3],
            'ignored' => true,
        ]);

        $this->assertSame('abcd', $result['long']);
        $this->assertCount(2, $result);
        $this->assertSame(['a' => '[truncated]', 'b' => '[truncated]'], $result['items']);
    }
}
