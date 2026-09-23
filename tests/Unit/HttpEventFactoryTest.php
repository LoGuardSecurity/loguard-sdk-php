<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Http\CapturePolicy;
use LoGuard\Sdk\Http\HttpEventFactory;
use LoGuard\Sdk\Http\RequestContext;
use PHPUnit\Framework\TestCase;

final class HttpEventFactoryTest extends TestCase
{
    public function testBuildsFrameworkNeutralEvent(): void
    {
        $context = new RequestContext(
            'post', '/login', 401, '10.0.0.2', '203.0.113.5, 10.0.0.2',
            'auth.login', null, ['User-Agent' => ['test'], 'Authorization' => ['secret']],
            ['email' => 'a@example.test', 'token' => 'secret']
        );
        $policy = new CapturePolicy(
            headers: ['User-Agent', 'Authorization'],
            queryByRoute: ['auth.login' => ['email', 'token']],
            trustedProxies: ['10.0.0.0/8']
        );

        $event = (new HttpEventFactory())->create($context, $policy);

        $this->assertSame('203.0.113.5', $event['ip']);
        $this->assertSame('http_request', $event['type']);
        $this->assertSame(['email' => 'a@example.test'], $event['meta']['query']);
        $this->assertArrayNotHasKey('Authorization', $event['meta']['headers']);
    }

    public function testTrackedStatusesUseGenericHttpRequestType(): void
    {
        $factory = new HttpEventFactory();
        $policy = new CapturePolicy();

        foreach ([400, 401, 403, 404, 429, 500, 502, 503] as $statusCode) {
            $context = new RequestContext(
                'get',
                '/test',
                $statusCode,
                '203.0.113.10'
            );

            $event = $factory->create($context, $policy);

            $this->assertNotNull($event);
            $this->assertSame(
                'http_request',
                $event['type'],
                "status {$statusCode} must remain generic HTTP telemetry"
            );
            $this->assertSame($statusCode, $event['status_code']);
        }
    }

}
