<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Signing;
use PHPUnit\Framework\TestCase;

final class SigningTest extends TestCase
{
    public function testSignatureIsHmacSha256OfTimestampDotBody(): void
    {
        $body = Signing::buildBody(['events' => [['type' => 'http_request']]]);
        [$sentBody, $headers] = Signing::sign('super-secret-key', $body);

        $this->assertSame($body, $sentBody, 'must sign exactly the bytes that get sent');

        $timestamp = $headers['X-LoGuard-Timestamp'];
        $expected = 'sha256=' . hash_hmac('sha256', $timestamp . '.' . $body, 'super-secret-key');
        $this->assertSame($expected, $headers['X-LoGuard-Signature']);
    }

    public function testHeadersIncludeRequiredFields(): void
    {
        [, $headers] = Signing::sign('k', Signing::buildBody(['a' => 1]));

        $this->assertArrayHasKey('X-Api-Key', $headers);
        $this->assertArrayHasKey('X-LoGuard-Timestamp', $headers);
        $this->assertArrayHasKey('X-LoGuard-Signature', $headers);
        $this->assertArrayHasKey('X-Request-ID', $headers);
        $this->assertSame('application/json', $headers['Content-Type']);
        $this->assertStringStartsWith('loguard-php-sdk/', $headers['User-Agent']);
    }

    public function testEachSignatureUsesAFreshRequestId(): void
    {
        $body = Signing::buildBody(['a' => 1]);
        [, $h1] = Signing::sign('k', $body);
        [, $h2] = Signing::sign('k', $body);

        $this->assertNotSame($h1['X-Request-ID'], $h2['X-Request-ID']);
    }

    public function testRequestIdIsWellFormedUuidV4(): void
    {
        $uuid = Signing::uuidV4();
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $uuid
        );
    }

    public function testBuildBodyIsDeterministicJson(): void
    {
        $a = Signing::buildBody(['x' => 1, 'y' => 'z']);
        $b = Signing::buildBody(['x' => 1, 'y' => 'z']);
        $this->assertSame($a, $b);
    }
}
