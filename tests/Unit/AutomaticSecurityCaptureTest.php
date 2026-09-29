<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Http\CapturePolicy;
use LoGuard\Sdk\Http\HttpEventFactory;
use LoGuard\Sdk\Http\RequestContext;
use PHPUnit\Framework\TestCase;

final class AutomaticSecurityCaptureTest extends TestCase
{
    public function testSecurityModeCapturesAttackQueryWithoutManualAllowlist(): void
    {
        $context = new RequestContext(
            'GET',
            '/',
            403,
            '161.97.68.109',
            null,
            null,
            null,
            [],
            [
                'id' => "1' AND 1=1--",
            ],
            null,
            null
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);
        self::assertSame(
            "1' AND 1=1--",
            $event['meta']['query']['id'] ?? null
        );
    }

    public function testSecurityModeDropsSensitiveQueryFields(): void
    {
        $context = new RequestContext(
            'GET',
            '/login',
            403,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [
                'username' => 'victim',
                'password' => 'super-secret',
                'access_token' => 'must-never-leave-process',
                'id' => "1' OR '1'='1",
            ],
            null,
            null
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);

        $query = $event['meta']['query'] ?? [];

        self::assertArrayNotHasKey('password', $query);
        self::assertArrayNotHasKey('access_token', $query);
        self::assertSame("1' OR '1'='1", $query['id'] ?? null);
    }

    public function testSecurityModeTracksSuccessfulRequestsToo(): void
    {
        $context = new RequestContext(
            'GET',
            '/search',
            200,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            ['q' => "' UNION SELECT 1--"],
            null,
            null
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);
        self::assertSame(200, $event['status_code']);
    }

    public function testSecurityModeDoesNotRequireNamedRoute(): void
    {
        $context = new RequestContext(
            'GET',
            '/unknown',
            404,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            ['id' => '1 AND 2=2'],
            null,
            null
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);
        self::assertSame(
            '1 AND 2=2',
            $event['meta']['query']['id'] ?? null
        );
    }

    public function testSecurityModeAutomaticallyCapturesJsonAttackBody(): void
    {
        $context = new RequestContext(
            'POST',
            '/search',
            200,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [],
            '{"search":"\\u0027 UNION SELECT 1--","category":"books"}',
            'application/json'
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);
        self::assertSame(
            "' UNION SELECT 1--",
            $event['meta']['body']['search'] ?? null
        );
        self::assertSame(
            'books',
            $event['meta']['body']['category'] ?? null
        );
    }

    public function testSecurityModeDropsSecretsFromJsonBodyRecursively(): void
    {
        $context = new RequestContext(
            'POST',
            '/login',
            401,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [],
            json_encode([
                'email' => "test' OR 1=1--",
                'password' => 'must-never-leave-process',
                'nested' => [
                    'access_token' => 'secret-token',
                    'search' => '<script>alert(1)</script>',
                ],
            ], JSON_THROW_ON_ERROR),
            'application/json'
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);

        $body = $event['meta']['body'] ?? [];

        self::assertArrayNotHasKey('password', $body);
        self::assertArrayNotHasKey('access_token', $body['nested'] ?? []);
        self::assertSame(
            "test' OR 1=1--",
            $body['email'] ?? null
        );
        self::assertSame(
            '<script>alert(1)</script>',
            $body['nested']['search'] ?? null
        );
    }

    public function testSecurityModeAutomaticallyCapturesFormBody(): void
    {
        $context = new RequestContext(
            'POST',
            '/login',
            403,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [],
            'username=admin%27+OR+1%3D1--&action=login',
            'application/x-www-form-urlencoded'
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);
        self::assertSame(
            "admin' OR 1=1--",
            $event['meta']['body']['username'] ?? null
        );
        self::assertSame(
            'login',
            $event['meta']['body']['action'] ?? null
        );
    }

    public function testSecurityModeDropsSecretsFromFormBody(): void
    {
        $context = new RequestContext(
            'POST',
            '/login',
            401,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [],
            'username=test&password=secret&token=abc123&q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
            'application/x-www-form-urlencoded'
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);

        $body = $event['meta']['body'] ?? [];

        self::assertArrayNotHasKey('password', $body);
        self::assertArrayNotHasKey('token', $body);
        self::assertSame('test', $body['username'] ?? null);
        self::assertSame(
            '<script>alert(1)</script>',
            $body['q'] ?? null
        );
    }

    public function testSecurityModeNeverCapturesUnsupportedBinaryBody(): void
    {
        $context = new RequestContext(
            'POST',
            '/upload',
            200,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [],
            "\x00\x01\x02\x03",
            'application/octet-stream'
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                securityCapture: true
            )
        );

        self::assertNotNull($event);
        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertTrue(
            $event['meta']['body_unsupported_content_type'] ?? false
        );
    }

    public function testSecurityModeRejectsOversizedBodyBeforeParsing(): void
    {
        $context = new RequestContext(
            'POST',
            '/api',
            200,
            '127.0.0.1',
            null,
            null,
            null,
            [],
            [],
            '{"value":"' . str_repeat('A', 1024) . '"}',
            'application/json'
        );

        $event = (new HttpEventFactory())->create(
            $context,
            new CapturePolicy(
                maxBodyBytes: 128,
                securityCapture: true
            )
        );

        self::assertNotNull($event);
        self::assertArrayNotHasKey('body', $event['meta']);
        self::assertTrue(
            $event['meta']['body_too_large'] ?? false
        );
    }


}
