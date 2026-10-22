<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Http\CapturePolicy;
use LoGuard\Sdk\Http\HttpEventFactory;
use LoGuard\Sdk\Http\RequestContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * JSON bodies sent under Content-Type: application/x-www-form-urlencoded (e.g.
 * `curl -d '{...}'`, common for bots) must be captured as JSON - not folded by
 * parse_str() into one mangled key - and must go through the same secret
 * stripping and bounds as a real application/json body.
 */
final class FormJsonSniffTest extends TestCase
{
    private const FORM = 'application/x-www-form-urlencoded';

    private function event(
        ?string $body,
        ?string $contentType,
        int $maxBodyBytes = 32768,
        int $maxJsonDepth = 8
    ): array {
        $context = new RequestContext(
            'POST',
            '/test',
            200,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [],
            $body,
            $contentType
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                maxBodyBytes: $maxBodyBytes,
                maxJsonDepth: $maxJsonDepth,
                securityCapture: true
            )
        );

        self::assertNotNull($event);

        return $event;
    }

    public function testJsonRpcBodyUnderFormContentTypeKeepsRealStructure(): void
    {
        $event = $this->event(
            '{"id": 1, "method": "eth_getWork", "params": []}',
            self::FORM
        );

        $body = $event['meta']['body'] ?? [];

        self::assertSame('eth_getWork', $body['method'] ?? null);
        self::assertSame(1, $body['id'] ?? null);
        self::assertCount(3, $body);
    }

    public function testSecretsInJsonUnderFormContentTypeAreRemoved(): void
    {
        $event = $this->event(
            '{"user":{"email":"alice@example.test","password":"s3cret","nested":{"token":"abc","q":"<script>1</script>"}}}',
            self::FORM
        );

        $user = $event['meta']['body']['user'] ?? [];

        self::assertSame('alice@example.test', $user['email'] ?? null);
        self::assertArrayNotHasKey('password', $user);
        self::assertArrayNotHasKey('token', $user['nested'] ?? []);
        self::assertSame('<script>1</script>', $user['nested']['q'] ?? null);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function jsonBodies(): array
    {
        return [
            'object' => ['{"a":1,"b":{"c":2}}'],
            'list' => ['[1,2,3]'],
            'secrets' => ['{"password":"x","q":"y"}'],
            'leading whitespace' => ["  \n{\"a\":1}"],
            'too deep' => ['{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}'],
        ];
    }

    #[DataProvider('jsonBodies')]
    public function testFormTypedJsonIsCapturedExactlyLikeApplicationJson(string $json): void
    {
        $asForm = $this->event($json, self::FORM);
        $asJson = $this->event($json, 'application/json');

        self::assertSame(
            $asJson['meta']['body'] ?? null,
            $asForm['meta']['body'] ?? null
        );
    }

    public function testRealFormBodyIsStillParsedAsForm(): void
    {
        $event = $this->event('a=1&b=two&c%5Bd%5D=3', self::FORM);

        $body = $event['meta']['body'] ?? [];

        self::assertSame('1', $body['a'] ?? null);
        self::assertSame('two', $body['b'] ?? null);
        self::assertSame('3', $body['c']['d'] ?? null);
    }

    public function testMalformedFormTypedJsonSetsParseError(): void
    {
        foreach ([
            '{"password":"secret", "q":',
            '[{"token":"secret"}',
        ] as $raw) {
            $result = \LoGuard\Sdk\Http\FieldPolicy::captureSecurityBody(
                $raw,
                self::FORM
            );

            self::assertTrue($result->parseError);
            self::assertSame([], $result->fields);
            self::assertSame(
                true,
                $result->toMeta()['body_parse_error'] ?? false
            );
            self::assertArrayNotHasKey('body', $result->toMeta());
        }
    }

    public function testOversizedFormTypedJsonIsNotCaptured(): void
    {
        $result = \LoGuard\Sdk\Http\FieldPolicy::captureSecurityBody(
            '{"password":"secret","method":"test"}',
            self::FORM,
            8
        );

        self::assertTrue($result->tooLarge);
        self::assertSame([], $result->fields);
        self::assertFalse($result->parseError);
    }

    public function testBrokenJsonUnderFormContentTypeDoesNotCrashOrLeak(): void
    {
        $event = $this->event('{"password":"s3cret", "q":', self::FORM);

        self::assertIsArray($event['meta']);
        self::assertStringNotContainsString(
            's3cret',
            json_encode($event['meta']['body'] ?? [], JSON_THROW_ON_ERROR)
        );
    }
}
