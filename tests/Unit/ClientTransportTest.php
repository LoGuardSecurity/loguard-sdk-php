<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;
use LoGuard\Sdk\Contracts\TransportInterface;
use PHPUnit\Framework\TestCase;

final class ClientTransportTest extends TestCase
{
    public function testInjectedTransportReceivesSanitizedPayload(): void
    {
        $transport = new class implements TransportInterface {
            public array $payload = [];

            public function send(string $url, array $headers, array $payload, float $timeout, int $attempts, string $method = 'POST', string $apiKey = ''): mixed
            {
                $this->payload = $payload;
                return ['ok' => true, 'accepted' => 1, 'alerts' => []];
            }
        };
        $client = new Client(new Config('lg_test'), $transport);

        $result = $client->event('custom', '127.0.0.1', '/test', 200, meta: [
            'safe' => 'value',
            'access_token' => 'must-not-leave-process',
        ]);

        $this->assertTrue($result->ok);
        $meta = $transport->payload['events'][0]['meta'];
        $this->assertInstanceOf(\stdClass::class, $meta);
        $this->assertSame('value', $meta->safe);
        $this->assertFalse(property_exists($meta, 'access_token'));
    }
}
