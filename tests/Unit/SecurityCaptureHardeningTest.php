<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Http\CapturePolicy;
use LoGuard\Sdk\Http\HttpEventFactory;
use LoGuard\Sdk\Http\RequestContext;
use PHPUnit\Framework\TestCase;

final class SecurityCaptureHardeningTest extends TestCase
{
    private function event(
        array $query = [],
        ?string $body = null,
        ?string $contentType = null,
        int $status = 200,
        int $maxBodyBytes = 32768,
        int $maxJsonDepth = 8
    ): array {
        $context = new RequestContext(
            'POST',
            '/test',
            $status,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            $query,
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

    public function testForbiddenNamesAreCaseInsensitiveInQuery(): void
    {
        $event = $this->event([
            'PASSWORD' => 'secret',
            'Access_Token' => 'secret',
            'q' => "' OR 1=1--",
        ]);

        $query = $event['meta']['query'] ?? [];

        self::assertArrayNotHasKey('PASSWORD', $query);
        self::assertArrayNotHasKey('Access_Token', $query);
        self::assertSame("' OR 1=1--", $query['q'] ?? null);
    }

    public function testForbiddenNamesAreRemovedRecursivelyFromQueryArrays(): void
    {
        $event = $this->event([
            'filter' => [
                'name' => 'alice',
                'password' => 'secret',
                'nested' => [
                    'token' => 'secret',
                    'q' => '<script>alert(1)</script>',
                ],
            ],
        ]);

        $filter = $event['meta']['query']['filter'] ?? [];

        self::assertSame('alice', $filter['name'] ?? null);
        self::assertArrayNotHasKey('password', $filter);
        self::assertArrayNotHasKey('token', $filter['nested'] ?? []);
        self::assertSame(
            '<script>alert(1)</script>',
            $filter['nested']['q'] ?? null
        );
    }

    public function testLongQueryValueIsBounded(): void
    {
        $event = $this->event([
            'q' => str_repeat('A', 10000),
        ]);

        $value = $event['meta']['query']['q'] ?? '';

        self::assertSame(4096, strlen($value));
    }

    public function testQueryParameterCountIsBounded(): void
    {
        $query = [];

        for ($i = 0; $i < 200; $i++) {
            $query['k' . $i] = 'v' . $i;
        }

        $event = $this->event($query);

        self::assertCount(
            64,
            $event['meta']['query'] ?? []
        );
    }

    public function testDeepQueryArrayIsDepthLimited(): void
    {
        $event = $this->event([
            'a' => [
                'b' => [
                    'c' => [
                        'd' => [
                            'e' => 'payload',
                        ],
                    ],
                ],
            ],
        ]);

        $query = $event['meta']['query'] ?? [];

        self::assertSame(
            '[depth-limited]',
            $query['a']['b']['c']['d']['e'] ?? null
        );
    }

    public function testJsonContentTypeWithCharsetIsSupported(): void
    {
        $event = $this->event(
            [],
            '{"q":"<script>alert(1)</script>"}',
            'application/json; charset=utf-8'
        );

        self::assertSame(
            '<script>alert(1)</script>',
            $event['meta']['body']['q'] ?? null
        );
    }

    public function testFormContentTypeWithCharsetIsSupported(): void
    {
        $event = $this->event(
            [],
            'q=admin%27+OR+1%3D1--',
            'application/x-www-form-urlencoded; charset=UTF-8'
        );

        self::assertSame(
            "admin' OR 1=1--",
            $event['meta']['body']['q'] ?? null
        );
    }

    public function testMalformedJsonIsFlaggedAndNeverCaptured(): void
    {
        $event = $this->event(
            [],
            '{"q":',
            'application/json'
        );

        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertTrue(
            $event['meta']['body_parse_error'] ?? false
        );
    }

    public function testScalarJsonIsRejected(): void
    {
        $event = $this->event(
            [],
            '"hello"',
            'application/json'
        );

        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertTrue(
            $event['meta']['body_parse_error'] ?? false
        );
    }

    public function testDeepJsonIsFlagged(): void
    {
        $body = json_encode([
            'a' => [
                'b' => [
                    'c' => [
                        'd' => [
                            'e' => 'payload',
                        ],
                    ],
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $event = $this->event(
            [],
            $body,
            'application/json',
            200,
            32768,
            3
        );

        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertTrue(
            $event['meta']['body_depth_exceeded'] ?? false
        );
    }

    public function testNestedJsonSecretsAreRemovedCaseInsensitively(): void
    {
        $body = json_encode([
            'user' => [
                'email' => 'alice@example.test',
                'PASSWORD' => 'secret',
                'nested' => [
                    'Access_Token' => 'secret',
                    'q' => "' UNION SELECT 1--",
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $event = $this->event(
            [],
            $body,
            'application/json'
        );

        $user = $event['meta']['body']['user'] ?? [];

        self::assertSame(
            'alice@example.test',
            $user['email'] ?? null
        );
        self::assertArrayNotHasKey('PASSWORD', $user);
        self::assertArrayNotHasKey(
            'Access_Token',
            $user['nested'] ?? []
        );
        self::assertSame(
            "' UNION SELECT 1--",
            $user['nested']['q'] ?? null
        );
    }

    public function testFormNestedSecretsAreRemoved(): void
    {
        $event = $this->event(
            [],
            'user[email]=alice%40example.test&user[password]=secret&user[nested][token]=abc&user[nested][q]=%3Cscript%3E1%3C%2Fscript%3E',
            'application/x-www-form-urlencoded'
        );

        $user = $event['meta']['body']['user'] ?? [];

        self::assertSame(
            'alice@example.test',
            $user['email'] ?? null
        );
        self::assertArrayNotHasKey('password', $user);
        self::assertArrayNotHasKey(
            'token',
            $user['nested'] ?? []
        );
        self::assertSame(
            '<script>1</script>',
            $user['nested']['q'] ?? null
        );
    }

    public function testEmptyBodyAddsNoBodyMetadata(): void
    {
        $event = $this->event(
            [],
            '',
            'application/json'
        );

        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertArrayNotHasKey(
            'body_parse_error',
            $event['meta']
        );
    }

    public function testNullContentTypeWithBodyIsUnsupported(): void
    {
        $event = $this->event(
            [],
            'q=test',
            null
        );

        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertTrue(
            $event['meta']['body_unsupported_content_type'] ?? false
        );
    }

    public function testMultipartBodyIsNeverCaptured(): void
    {
        $event = $this->event(
            [],
            '--boundary' . "\r\n"
                . 'Content-Disposition: form-data; name="q"' . "\r\n\r\n"
                . '<script>alert(1)</script>' . "\r\n"
                . '--boundary--',
            'multipart/form-data; boundary=boundary'
        );

        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertTrue(
            $event['meta']['body_unsupported_content_type'] ?? false
        );
    }

    public function testVendorJsonContentTypeIsSupported(): void
    {
        $event = $this->event(
            [],
            '{"q":"attack-shaped-value"}',
            'application/problem+json; charset=utf-8'
        );

        self::assertSame(
            'attack-shaped-value',
            $event['meta']['body']['q'] ?? null
        );
    }

    public function testQueryParameterBudgetIsGlobalAcrossNestedTree(): void
    {
        $left = [];
        $right = [];

        for ($i = 0; $i < 40; $i++) {
            $left['l' . $i] = 'v';
            $right['r' . $i] = 'v';
        }

        $event = $this->event([
            'left' => $left,
            'right' => $right,
        ]);

        $query = $event['meta']['query'] ?? [];

        $countEntries = function (array $value) use (&$countEntries): int {
            $count = 0;

            foreach ($value as $nested) {
                $count++;

                if (is_array($nested)) {
                    $count += $countEntries($nested);
                }
            }

            return $count;
        };

        self::assertLessThanOrEqual(
            64,
            $countEntries($query),
            'automatic query capture must enforce one global field budget'
        );
    }

    public function testJsonBodyParameterBudgetIsGlobalAcrossNestedTree(): void
    {
        $left = [];
        $right = [];

        for ($i = 0; $i < 40; $i++) {
            $left['l' . $i] = 'v';
            $right['r' . $i] = 'v';
        }

        $event = $this->event(
            [],
            json_encode([
                'left' => $left,
                'right' => $right,
            ], JSON_THROW_ON_ERROR),
            'application/json'
        );

        $body = $event['meta']['body'] ?? [];

        $countEntries = function (array $value) use (&$countEntries): int {
            $count = 0;

            foreach ($value as $nested) {
                $count++;

                if (is_array($nested)) {
                    $count += $countEntries($nested);
                }
            }

            return $count;
        };

        self::assertLessThanOrEqual(
            64,
            $countEntries($body),
            'automatic body capture must enforce one global field budget'
        );
    }

}
